# Issue #594 — Phase 2: Profile JSON Schema Restructuring

**Status:** Design complete, ready for implementation planning.
**Upstream issue:** https://github.com/always-further/nono/issues/594
**Scope:** Phase 2 of the two-phase split. Phase 1 (CLI namespace consolidation) shipped in 5ff9bc3.

## Problem

Phase 1 moved `nono policy *` subcommands under `nono profile *`, delivering a
cleaner CLI surface with zero migration risk for existing profile files.
Phase 2 restructures the profile JSON itself so related concerns live
together, eliminating the remaining user-facing use of "policy" in
configuration files.

All nine migrations listed in issue #594 cross sections (e.g.
`policy.add_allow_read` → `filesystem.read`). None is a same-section rename,
so `#[serde(alias)]` alone does not cover them — legacy capture structs are
required.

Answers to the open questions in the issue:

- **Deprecation timeline:** short, driven by nono's rapid release cadence.
  Encoded as `remove_by=v1.0.0` on every deprecation marker. A single tracking
  issue (#594 itself) holds the inventory; `scripts/test-list-aliases.sh`
  produces a machine-readable version from source.
- **Schema version bump:** not needed. Serde aliases and legacy capture
  structs handle backward compatibility without a `schema_version` key.

## Goals

- New profile JSON schema per issue #594: `groups.include/exclude`,
  `commands.allow/deny`, expanded `filesystem` section, narrowed `security`
  section, no top-level `policy` key.
- CLI flag rename: `--override-deny` → `--bypass-protection`.
- All repo-shipped profiles (`qa-profiles/*.json`, built-ins) migrated to the
  new schema in the same PR.
- Old keys and old flag continue to work during the deprecation window with
  warnings on load, on `nono profile validate`, and on CLI usage.
- `/// ALIAS(canonical=…, introduced=…, remove_by=…, issue=…)` marker on
  every deprecated alias in the codebase, enforced by CI.
- Removal later is mechanical — a documented, auditable sequence of deletions.

## Non-Goals

- Renaming the internal `policy.json` data file or `policy.rs` module.
  "Policy" stays as internal vocabulary.
- Changes to `network`, `workdir`, `hooks`, `rollback`, `open_urls`,
  `secrets`, or any section not called out in issue #594.
- New schema fields or functional changes beyond the restructure.
- A runtime `nono internal deprecations` subcommand. The source-of-truth is
  the `/// ALIAS` comments, surfaced via `scripts/test-list-aliases.sh`.
- Splitting the work into multiple PRs. Security-critical config parsing
  deserves one atomic, reviewable unit.

## PR Boundary

Single PR against `main`, branch `issue-594-phase-2-schema`. Logical commit
groups:

1. New canonical structs + `Profile` field renames.
2. Legacy capture layer (`deprecated_schema.rs`).
3. Deprecation warning plumbing (load-time, `validate`, CLI).
4. Built-in profile migration + `qa-profiles/*.json` migration.
5. Legacy fixture suite.
6. Doc updates (embedded guide, mdx pages).
7. Enforcement scripts (`test-list-aliases.sh`, `lint-docs`).

## Data Model

### New canonical structs

Live in `crates/nono-cli/src/profile/mod.rs`:

```rust
GroupsConfig {
    include: Vec<String>,
    exclude: Vec<String>,
}

CommandsConfig {
    allow: Vec<String>,
    deny:  Vec<String>,
}

FilesystemConfig {  // expanded
    allow, read, write,              // unchanged
    allow_file, read_file, write_file, // unchanged
    deny: Vec<String>,                // new (was policy.add_deny_access)
    bypass_protection: Vec<String>,   // new (was policy.override_deny)
}

SecurityConfig {  // narrowed
    signal_mode, process_info_mode, ipc_mode,
    capability_elevation, wsl2_proxy_policy,
    // removed: groups, allowed_commands
}

Profile {
    groups:   GroupsConfig,
    commands: CommandsConfig,
    // policy: PolicyPatchConfig — DELETED from canonical
    ...
}
```

### Migration table

| Old location                   | New location                   |
|--------------------------------|--------------------------------|
| `security.groups`              | `groups.include`               |
| `security.allowed_commands`    | `commands.allow`               |
| `policy.exclude_groups`        | `groups.exclude`               |
| `policy.add_allow_read`        | `filesystem.read`              |
| `policy.add_allow_write`       | `filesystem.write`             |
| `policy.add_allow_readwrite`   | `filesystem.allow`             |
| `policy.add_deny_access`       | `filesystem.deny`              |
| `policy.add_deny_commands`     | `commands.deny`                |
| `policy.override_deny`         | `filesystem.bypass_protection` |

### Parsing architecture — two-layer

**Layer 1: Canonical deserialization.** Canonical structs keep
`#[serde(deny_unknown_fields)]`. They reject unknown keys, including the old
ones.

**Layer 2: Legacy capture.** Transient types on the deserialize path, drained
to canonical in `From<ProfileDeserialize> for Profile`:

- `LegacySecurityFields { groups, allowed_commands }` — captured by a
  `RawSecurityConfig` wrapper that accepts both new keys (`signal_mode`, etc.)
  and old keys (`groups`, `allowed_commands`). Does not have
  `deny_unknown_fields`. In `From`, splits into canonical `SecurityConfig`
  plus drains the legacy pair into `Profile.groups.include` /
  `Profile.commands.allow`.
- `LegacyPolicyPatch` — the existing `PolicyPatchConfig` relocated and
  renamed. Populated when top-level `"policy"` key is present. Drains into
  `Profile.groups.exclude`, `Profile.commands.deny`, and
  `Profile.filesystem.{read,write,allow,deny,bypass_protection}`.

Every drain emits a deprecation warning naming the legacy key, the canonical
key, `remove_by=v1.0.0`, and `#594`. One warning per legacy key per file.

This approach reuses the existing `ProfileDeserialize` + `From` pattern (see
`profile/mod.rs:1257–1330`) — no new architectural concept. It is the only
clean option given that all nine migrations cross sections.

## Deprecation Marker Convention

All aliases carry:

```rust
/// ALIAS(canonical="filesystem.read", introduced="v0.41.0", remove_by="v1.0.0", issue="#594")
#[serde(alias = "add_allow_read")]
pub read: Vec<String>,
```

Required on every:

- `#[serde(alias = …)]` in `crates/`.
- `#[serde(rename = "new", alias = "old")]` where `rename` differs from field
  name.
- `#[arg(long = "…", alias = …)]` in clap definitions.
- Field of a legacy capture struct (e.g. every field of `LegacyPolicyPatch`).

`canonical` is the user-visible name (profile-key path for JSON, `--flag` for
CLI). All four fields mandatory.

**Scope of enforcement.** New phase 2 aliases must carry the marker. Existing
aliases (`NetworkConfig::allow_domain`, `credentials`, `open_port`,
`upstream_proxy`, `upstream_bypass`; `Profile`'s `secrets`/`brokered_commands`
aliases; `trust/types.rs:24`) are retrofitted with markers in the same PR.
They get `remove_by` dates or an explicit `remove_by="indefinite"` that the
script flags separately in its inventory output.

## CLI Flag Rename

`--override-deny` → `--bypass-protection`. Clap definition:

```rust
/// ALIAS(canonical="--bypass-protection", introduced="v0.41.0", remove_by="v1.0.0", issue="#594")
#[arg(long = "bypass-protection", alias = "override-deny", value_name = "PATH")]
pub bypass_protection: Vec<PathBuf>,
```

The Rust field renames to `bypass_protection` everywhere — internal, no
backcompat needed. Sites per grep: `cli.rs:866,1050,1115,1211,1238` and
`cli.rs:2919–2956` (four tests). Rename propagates to `policy.rs`,
`sandbox_prepare.rs`, `learn.rs`, and everywhere `args.sandbox.override_deny`
is read.

**Warning emission.** Clap does not emit alias-hit warnings natively, so
`main()` inspects `std::env::args_os()` once for `--override-deny` /
`--override-deny=` occurrences and emits one stderr warning per invocation
(matching phase 1 style):

```
warning: '--override-deny' is deprecated and will be removed in v1.0.0;
use '--bypass-protection' (#594)
```

## Deprecated-Code Isolation

All deprecation logic lives in one new module:
`crates/nono-cli/src/deprecated_schema.rs` (naming parallel to phase 1's
`deprecated_policy.rs`). Module header:

```rust
// DEPRECATED: delete this file when v1.0.0 deprecations are removed.
// Removal steps:
//   1. Delete this file.
//   2. Delete `mod deprecated_schema;` in main.rs / lib.rs.
//   3. In cli.rs: remove `alias = "override-deny"` from the two clap flag
//      defs and delete the `warn_for_deprecated_flags()` call in main.
//   4. In profile/mod.rs: delete `legacy_policy` + `legacy_security_fields`
//      from ProfileDeserialize and narrow the `security` field back to
//      SecurityConfig.
//   5. Delete crates/nono-cli/tests/fixtures/legacy_profiles/.
//   6. Run scripts/test-list-aliases.sh — inventory should be empty.
//   7. `make ci` must pass.
```

**Contents.**

- `warn_for_deprecated_flags(args: &[OsString])`.
- `LegacyPolicyPatch`, `RawSecurityConfig`, `LegacySecurityFields`.
- `drain_legacy_into_canonical(&mut ProfileDeserialize)` helper.
- `emit_deprecation_warning(legacy, canonical, remove_by, issue)` — shared
  formatter used by CLI, load-time, and `validate`.

**Callsite rule.** Only two entry points touch this module:

- `main()` calls `deprecated_schema::warn_for_deprecated_flags`.
- `impl From<ProfileDeserialize> for Profile` calls
  `deprecated_schema::drain_legacy_into_canonical`.

No other file may import from `deprecated_schema`. Enforced by
`scripts/test-list-aliases.sh`: greps for `use crate::deprecated_schema` and
fails if any unapproved file imports it.

## Enforcement Scripts

### `scripts/test-list-aliases.sh`

Runs in `make ci`. POSIX shell + `grep -RE` only. No `rg` / `ripgrep`
dependency, keeping parity with `make ci`'s current toolchain (`cargo` +
`cargo-audit`).

Responsibilities:

1. `grep -REn '/// ALIAS\(' crates/` — collect all markers and the attributes
   they annotate.
2. Validate each marker parses and carries all four fields; fail if any
   missing.
3. Assert every `#[serde(alias = …)]`, `#[serde(rename = …)]` (where rename
   differs from field), and `#[arg(..., alias = …)]` in `crates/` has a
   `/// ALIAS` immediately above; fail if naked.
4. Assert only approved files import `deprecated_schema` /
   `deprecated_policy`.
5. Print inventory grouped by `remove_by`, nearest-first. Flag
   `remove_by="indefinite"` entries separately.

Size target: ~80 lines of shell. If patterns grow complex, escalate to a
small Rust helper — not to `rg`, to preserve the baseline.

### `make lint-docs` (folded into `make ci`)

Greps forbidden tokens across `docs/**/*.mdx`, `README.md`,
`crates/**/data/*.md`, and Rust source using POSIX `grep -RE`:

```
policy\.add_
policy\.override_deny
policy\.exclude_groups
security\.groups
security\.allowed_commands
--override-deny
```

Allowlist (exempt paths):

- `crates/nono-cli/src/deprecated_schema.rs`
- `crates/nono-cli/src/deprecated_policy.rs`
- `crates/nono-cli/tests/fixtures/legacy_profiles/`
- `docs/plans/` (historical design docs)
- The CHANGELOG (auto-generated by `git-cliff`; never manually edited).

## Test Strategy

### Fixture layout

New directory `crates/nono-cli/tests/fixtures/legacy_profiles/`:

- One file per deprecated key, nine files total.
- `legacy_all_keys.json` — every deprecated key in one realistic profile.
- `canonical_equivalent_of_all_keys.json` — same semantic content, new
  schema.

### Unit tests (`crates/nono-cli/src/profile/legacy_tests.rs`)

Per single-key fixture:

1. `Profile::from_file()` succeeds.
2. The canonical field it drains into is populated correctly.
3. Stderr warning is emitted exactly once, contains the legacy key, the
   canonical key, and `v1.0.0`.

### Integration tests

- `legacy_all_keys.json` and `canonical_equivalent_of_all_keys.json` produce
  byte-equal output from `nono profile show --json`.
- `nono profile validate legacy_all_keys.json` exits 0 and emits all 9
  deprecation warnings.
- `nono profile diff legacy_all_keys.json canonical_equivalent_of_all_keys.json`
  shows no semantic diff.

### Enforcement tests

- `scripts/test-list-aliases.sh` invoked from a `#[test]` in
  `crates/nono-cli/tests/alias_inventory.rs` (shells out, asserts exit 0).
- Embedded `profile-authoring-guide.md` greps clean of forbidden tokens
  (phase 1 precedent).
- `nono profile schema` snapshot: new fields present, old absent. Old keys
  are accepted via aliases but not advertised.

## `nono profile validate` Behavior

Deprecation feedback is surfaced prominently on `validate`:

- Always parses; legacy keys never cause failure during the deprecation
  window.
- Per deprecated key: emit one line,
  `warning: deprecated key 'policy.add_allow_read' — use 'filesystem.read' instead (removed in v1.0.0, #594)`.
- Exit code stays `0` if the file is otherwise valid.
- New `--strict` flag upgrades deprecation warnings to errors (exit `2`).
  Useful for downstream CI. Off by default.
- Final summary line:
  `found 9 deprecated keys; run 'nono profile guide' for migration mapping`.

Same warning emitter (`emit_deprecation_warning`) used at load time and here.

## Documentation and References

Inventory (carried in the implementation plan, enforced by `make lint-docs`):

1. **Embedded profile guide** — `crates/nono-cli/data/profile-authoring-guide.md`.
   Rewrite examples; add a "Migrating from the old schema" section with
   before/after snippets for every key mapping and a link to issue #594.
2. **Site docs** — `docs/cli/features/profiles-groups.mdx`,
   `profile-authoring.mdx`, `profile-introspection.mdx`,
   `usage/flags.mdx`, `internals/*`.
3. **Repo-shipped profile JSON** — `qa-profiles/*.json` and every profile
   in `crates/nono-cli/src/profile/builtin.rs`. All migrate to new schema.
4. **Legacy test fixtures** — only legitimate home of old keys. Allowlisted
   in `make lint-docs`.
5. **Rustdoc comments** — `PolicyPatchConfig`'s rustdoc becomes
   `LegacyPolicyPatch`'s rustdoc (with `/// ALIAS` on each field).
6. **Error and suggestion strings** — `policy.rs`, `profile_cmd.rs`,
   `learn.rs`. All user-facing strings reference canonical keys.
7. **README** — any quick-start example.
8. **JSON schema output** — `nono profile schema` emits the new schema only.
9. **Integration shell tests** — `tests/integration/*.sh`.

**CHANGELOG is auto-generated** by `git-cliff` from commit messages — not
manually edited. The final PR's commit carries the deprecation signal in its
body so `git-cliff` renders a sensible entry (`feat(profile)!: restructure
profile JSON schema (#594)` with a body listing the nine key moves and
`remove_by=v1.0.0`).

## Rollout and Verification

### Prerequisites (CLAUDE.md policy compliance)

1. Post a phase 2 kickoff comment on issue #594 stating scope, approach
   (two-layer parsing, legacy capture structs), and `remove_by=v1.0.0`.
   Issue #594 serves as the deprecation tracking issue for the whole phase —
   no separate issue.
2. Mirror in upstream `always-further/nono` if not already present.

### Verification gates (all must pass before merge)

1. `make ci` passes — clippy `-D warnings -D clippy::unwrap_used`, fmt, full
   test suite, `cargo audit`.
2. `scripts/test-list-aliases.sh` passes and prints the expected inventory
   (9 new for #594, plus retrofitted existing aliases).
3. `make lint-docs` passes — zero forbidden tokens outside allowlist.
4. `nono profile validate legacy_all_keys.json` emits 9 warnings, exits 0.
5. `nono profile show --json legacy_all_keys.json` byte-equals
   `nono profile show --json canonical_equivalent_of_all_keys.json`.
6. `nono profile guide` output contains no forbidden tokens.
7. Built-ins and `qa-profiles/*.json` parse and validate clean on new schema.
8. Schema snapshot test passes.

### Risks

- *Hidden legacy-canonical drift* (legacy fixture passes, but a new canonical
  field has no legacy equivalent check). Mitigated: byte-equal `show --json`
  cross-check covers the whole resolved state.
- *Built-in profile regression during migration*. Mitigated: all built-ins
  on new schema; dedicated legacy fixtures exercise the alias path on every
  commit.
- *Forgotten alias metadata*. Mitigated: `scripts/test-list-aliases.sh` fails
  CI if any `#[serde(alias)]` or `#[arg(alias)]` lacks its `/// ALIAS` tag.
- *Cross-section parsing edge cases* (e.g. both `security.groups` and
  `groups.include` present in one file). Mitigated: legacy drain runs first,
  canonical values take precedence; a test fixture exercises the collision.

### Post-merge

Post a summary on issue #594 linking the PR. Issue stays open until v1.0.0
removal lands. The removal PR is the mechanical sequence documented in
`deprecated_schema.rs` + the phase-1 `deprecated_policy.rs` removal.
