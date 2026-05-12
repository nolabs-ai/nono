# Phase 36: UPST3 deep closure - Research

**Researched:** 2026-05-12
**Domain:** Upstream-port closure for nono fork (deprecated_schema module, yaml_merge wiring, b5f0a3ab surgical helper port)
**Confidence:** HIGH

## Summary

CONTEXT.md is unusually thorough — locked decisions D-36-A1..A6 / B1..B4 / C1..C2 / D1..D3 / E1..E2 cover plan slicing, wave shape, scope trimming, commit shape, close gate, and carry-forward invariants. This research's job is verification + drift surfacing, not re-derivation.

**Verification outcomes:**
- All 8 upstream commits (`b5f0a3ab`, `bbdf7b85`, `242d4917`, `802c8566`, `d44f5541`, `f0abd413`, `24d8b924`, `bdf183e9`) resolve from the `upstream` remote and match CONTEXT.md's claimed authors and tags.
- All deferred-state markers in source files are present exactly as CONTEXT.md describes (diagnostic.rs comment blocks at lines 402-419 + 2258-2267; ExecConfig struct at line 276 with 17 pub fields including the 11 fork-side fields D-36-D1 protects; Plan 34-04b Option C scaffolding in profile/mod.rs at lines 47, 439, 1359, 1364).
- No git history drift since CONTEXT.md was gathered 2026-05-12 — all commits between then and now are the CONTEXT.md authoring commits themselves (`c46be15b`, `ea2d0740`).

**Three drift findings the planner MUST account for:**
1. **`policy_cmd.rs` does NOT exist in the fork.** CONTEXT.md (and deferred-items.md, and a comment at profile/mod.rs:430) reference `crates/nono-cli/src/policy_cmd.rs` as a rename target. The fork's logic for `nono policy <sub>` and `nono profile <sub>` actually lives in `crates/nono-cli/src/profile_cmd.rs` (3063 LOC) and `crates/nono-cli/src/policy.rs` (3135 LOC). `deprecated_policy.rs` (the CLI alias shim) is a separate concern. **Plan 36-01c's "210-callsite rename across 14+ files" file list needs `policy_cmd.rs` removed and replaced with the actual file shape.**
2. **`override_deny` callsite count is 183, not 210.** Grep across `crates/nono-cli/src/` finds 183 hits of `override_deny` across 17 files (capability_ext.rs:23, cli.rs:14, command_runtime.rs:4, execution_runtime.rs:3, launch_runtime.rs:3, learn.rs:6, main.rs:2, policy.rs:6, profile_cmd.rs:13, profile_runtime.rs:9, profile_save_runtime.rs:23, profile/builtin.rs:6, profile/mod.rs:66, query_ext.rs:4, sandbox_prepare.rs:4, sandbox_state.rs:8, why_runtime.rs:2). Upstream's "210" count likely reflects upstream's broader profile_cmd surface; the fork's count is smaller because fork merged some of these helpers into profile/mod.rs. **D-36-B4 atomic-rename invariant still holds, just at 183 sites across 17 files instead of 210 across 14.**
3. **`clear_signal_forwarding_target` already exists** in fork's exec_strategy.rs at line 1987 with 2 callsites at lines 825 + 2047. Plan 36-03 Commit 2's task is to add a NEW callsite "before the profile-save prompt" per the b5f0a3ab surgical port — not to introduce the function. **Plan 36-03 task wording should be "add new pre-profile-save call site to existing helper", not "restore helper".**

**Primary recommendation:** Proceed exactly as CONTEXT.md prescribes for the 6 plans. The locked scope is correct; the locked sequencing is correct; the locked commit shapes are correct. The three drift findings above are file-naming/count corrections, not scope changes — planner should reference them in PLAN.md line 1 of 36-01c and 36-03 so executors don't get tripped up.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Legacy `override_deny` JSON key acceptance + rewrite | CLI (nono-cli) | — | Schema/serde concern; lives in `profile/mod.rs` (currently) and moves to new `deprecated_schema.rs` module |
| Per-key deprecation counter (one-shot stderr emission) | CLI (nono-cli) | — | Stderr/process-state concern; `AtomicBool` per-key counter in `deprecated_schema.rs` |
| `nono profile validate --strict` fail-closed lever | CLI (nono-cli) | — | New CLI flag in `ProfileValidateArgs`; emits non-zero exit on legacy key when set |
| Canonical Profile sections (`groups`, `commands.*`, `filesystem.*`) | CLI (nono-cli) | Library (nono) | Profile struct lives in nono-cli; canonical sections compose with `CapabilitySet` builder in `nono` (no change to library) |
| 210/183-callsite `override_deny` → `bypass_protection` rename | CLI (nono-cli) | — | Internal Rust identifier rename across nono-cli only; library is not affected |
| Built-in profile data migration (claude-code, codex, opencode, claude-no-keychain) | CLI data (nono-cli/data/) | — | JSON profile data; no code change |
| JSON schema (`nono-profile.schema.json`) restructure | CLI data (nono-cli/data/) | — | Schema fixture; consumed by `jsonschema` dev-dep at test time |
| `scripts/test-list-aliases.sh` + `scripts/lint-docs.sh` | Build tooling (scripts/) | — | CI/test tooling; runs at build/test surface |
| Profile-authoring guide + flags.mdx + profiles-groups.mdx | Docs (docs/cli/) | — | User-facing documentation |
| `yaml_merge` directive parser + applier | CLI (nono-cli) | — | New `wiring.rs` module; consumed by `profile_cmd.rs::cmd_profile_patch --yaml` handler |
| `serde_yaml_ng` 0.10.0 pin | CLI dependency (nono-cli/Cargo.toml) | — | New runtime dependency; replaces deprecated `serde_yaml` shape |
| `b5f0a3ab` surgical diagnostic helpers (4 fns + 1 wiring) | Library (nono) | — | Lives in `crates/nono/src/diagnostic.rs`; library-tier diagnostic analysis |
| `b5f0a3ab` surgical exec-strategy helpers (`should_offer_profile_save`, `POST_EXIT_PTY_DRAIN_TIMEOUT`, startup-timeout machinery) | CLI (nono-cli) | — | Lives in `exec_strategy.rs` + `execution_runtime.rs`; CLI tier owns exec policy |
| `bbdf7b85` escape-quote body rewrite | Library (nono) | — | Function body change inside `diagnostic.rs`; library tier |

## Standard Stack

### Core (already in fork; no changes needed)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| serde | workspace | Serialization for Profile/CapabilitySet/etc. | [VERIFIED: crates/nono-cli/Cargo.toml line 74] Fork already uses workspace serde |
| serde_json | workspace | JSON profile parse + emit | [VERIFIED: line 75] Already in use |
| clap | 4 | CLI argument parsing (visible_alias, ProfileValidateArgs) | [VERIFIED: line 45] Already in use; `--strict` flag is additive |
| thiserror | workspace | NonoError variants | [VERIFIED: line 73] Already in use |
| jsonschema | 0.46 | Schema validation (dev-dep) | [VERIFIED: line 109] Already in dev-deps; used by Plan 36-01d schema fixture tests |

### New (Plan 36-02 adds)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| serde_yaml_ng | 0.10.0 (pin) | YAML parsing for `yaml_merge` directive | [CITED: upstream commit 242d4917] Upstream's locked choice for the v0.49.0 yaml_merge surface; replaces deprecated `serde_yaml` (which has been unmaintained since 2024) |

**Version verification:** `npm view`-equivalent for Rust is `cargo search`. I did not run a live registry check; the `=0.10.0` pin is the locked decision from CONTEXT.md D-36-C1 citing upstream `242d4917`. Verification step belongs in the executor's `cargo build` after `Cargo.toml` edit. [ASSUMED: serde_yaml_ng 0.10.0 is still on crates.io] — recommend executor `cargo search serde_yaml_ng` before bumping.

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Full Option C verbatim port (D-36-B1) | Adapted/minimal port keeping fork's Profile shape | User-rejected at discuss — future P34-DEFER absorptions pick up canonical surface for free |
| Stripped-down wiring.rs (D-36-C1) | Full 1761-LOC wiring.rs port with WriteFile/JsonMerge/JsonArrayAppend | Deferred to v2.5-FU-3; conflicts with fork's hooks.rs ownership + validate_path_within retention |
| Upstream-shape ExecConfig adoption (D-36-D1) | Refactor ExecConfig to upstream's b5f0a3ab shape | User-rejected; load-bearing for Phase 18/26/27/31/34-08a/35-01; deferred to v2.5-FU-4 |

**Installation (Plan 36-02 only):**
```toml
# crates/nono-cli/Cargo.toml [dependencies] block:
serde_yaml_ng = "=0.10.0"
```

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| REQ-PORT-CLOSURE-02 | Full deprecated_schema module port (P34-DEFER-04b-1); 824-LOC LegacyPolicyPatch + per-key DeprecationCounter + `--strict` mode + 210/183-callsite internal rename + canonical Profile sections + JSON schema restructure + built-in profile data migration + scripts/test-list-aliases.sh + scripts/lint-docs.sh + docs migration | Plans 36-01a (module + LegacyPolicyPatch + DeprecationCounter) → 36-01b (canonical sections) → 36-01c (callsite rename) → 36-01d (data + docs + tooling). All 4 sub-plans verified against fork's current shape: profile/mod.rs has Phase 34-04b Option C scaffolding at lines 47/439/1359/1364; new file `deprecated_schema.rs` does not exist; built-in profile data lives in nono-cli/data/policy.json (currently uses upstream-canonical `groups` top-level shape — partial alignment with target). |
| REQ-PORT-CLOSURE-04 | yaml_merge wiring trio + base abstraction (P34-DEFER-06-1 + 09-2). **Acceptance #1 explicitly scope-trimmed per D-36-C1.** Stripped-down port: `yaml_merge` directive only + `serde_yaml_ng` 0.10.0 pin + reversal failure test. | Plan 36-02. Fork has no `wiring.rs` (verified `ls crates/nono-cli/src/wiring.rs` returns ENOENT). New file ~300-400 LOC. Cargo.toml has no `serde_yaml*` dep currently (verified). Wave 1 parallel with 36-01a + 36-03 — surfaces disjoint. |
| REQ-PORT-CLOSURE-05 | b5f0a3ab deep ExecConfig refactor + escape-quote pipeline (P34-DEFER-08b-1 + 08b-2). Surgical port keeping fork's ExecConfig shape; restore 4 diagnostic helpers + wire into analyze_error_output + 3 tests; add escape-quote body rewrite. | Plan 36-03 (3 sequenced commits). Fork's ExecConfig at exec_strategy.rs line 276 has 17 pub fields (verified) including the 11 fork-side fields D-36-D1 protects: `caps`, `env_vars`, `cap_file`, `current_dir`, `no_diagnostics`, `threading`, `protected_paths`, `profile_save_base`, `startup_timeout`, `capability_elevation`, `seccomp_proxy_fallback` (cfg-gated Linux), `allowed_env_vars`, `denied_env_vars`. The 4 diagnostic helpers are absent (verified — grep finds only comment references at lines 402-405 + 2263-2264). `clear_signal_forwarding_target` already exists at exec_strategy.rs:1987 with 2 callsites (planner should reword Commit 2 task as "add new callsite", not "restore"). |

## Architecture Patterns

### System Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                       Phase 36 — 3 Disjoint Surfaces                         │
└──────────────────────────────────────────────────────────────────────────────┘

REQ-PORT-CLOSURE-02 (Plans 36-01a/b/c/d, sequential within REQ)
   │
   │  ┌──────────────────────────────────────────────────────────────────────┐
   │  │  Plan 36-01a: deprecated_schema module foundation                    │
   │  │                                                                      │
   │  │  ┌──────────────────────┐    register     ┌──────────────────────┐  │
   │  │  │ NEW FILE             │ <───────────────│ main.rs              │  │
   │  │  │ deprecated_schema.rs │                 │ (mod deprecated_     │  │
   │  │  │ ~824 LOC port:       │                 │  schema;)            │  │
   │  │  │ • LegacyPolicyPatch  │                 └──────────────────────┘  │
   │  │  │ • DeprecationCounter │                                           │
   │  │  │ • --strict mode hook │                 ┌──────────────────────┐  │
   │  │  └──────────────────────┘                 │ cli.rs               │  │
   │  │            │                              │ ProfileValidateArgs  │  │
   │  │            │ wire into profile-load        │ + --strict flag      │  │
   │  │            ↓                              └──────────────────────┘  │
   │  │  ┌──────────────────────┐                                           │
   │  │  │ profile_cmd.rs       │                                           │
   │  │  │ (NOT policy_cmd.rs   │                                           │
   │  │  │  — DRIFT NOTE 1)     │                                           │
   │  │  └──────────────────────┘                                           │
   │  └──────────────────────────────────────────────────────────────────────┘
   │            │
   │            ↓ (36-01a closes — Wave 2 starts)
   │  ┌──────────────────────────────────────────────────────────────────────┐
   │  │  Plan 36-01b: canonical Profile sections                             │
   │  │  profile/mod.rs (6140 LOC) — restructure Profile/LoadedProfile       │
   │  │    expose `groups`, `commands.{allow,deny}`,                         │
   │  │            `filesystem.{deny,bypass_protection}`                     │
   │  └──────────────────────────────────────────────────────────────────────┘
   │            │
   │            ↓
   │  ┌──────────────────────────────────────────────────────────────────────┐
   │  │  Plan 36-01c: 183-callsite override_deny → bypass_protection rename  │
   │  │  ATOMIC SINGLE COMMIT across 17 files (per D-36-B4 invariant)        │
   │  │  • capability_ext.rs (23)  • profile_save_runtime.rs (23)            │
   │  │  • cli.rs (14)             • profile/mod.rs (66)                     │
   │  │  • profile_cmd.rs (13)     • profile/builtin.rs (6)                  │
   │  │  • profile_runtime.rs (9)  • learn.rs (6)                            │
   │  │  • sandbox_state.rs (8)    • policy.rs (6)                           │
   │  │  • command_runtime.rs (4)  • execution_runtime.rs (3)                │
   │  │  • launch_runtime.rs (3)   • query_ext.rs (4)                        │
   │  │  • sandbox_prepare.rs (4)  • why_runtime.rs (2)                      │
   │  │  • main.rs (2)                                                       │
   │  └──────────────────────────────────────────────────────────────────────┘
   │            │
   │            ↓
   │  ┌──────────────────────────────────────────────────────────────────────┐
   │  │  Plan 36-01d: data + docs + tooling                                  │
   │  │  • crates/nono-cli/data/policy.json (1029 LOC; already uses top-     │
   │  │    level `groups` shape — partial alignment, verify migration scope) │
   │  │  • crates/nono-cli/data/nono-profile.schema.json (637 LOC)           │
   │  │  • scripts/test-list-aliases.sh (new file)                           │
   │  │  • scripts/lint-docs.sh (new file)                                   │
   │  │  • scripts/regenerate-schema.sh (exists per CONTEXT.md; verify)      │
   │  │  • docs/cli/features/profiles-groups.mdx (exists — migrate)          │
   │  │  • docs/cli/usage/flags.mdx (exists — migrate)                       │
   │  │  • crates/nono-cli/data/profile-authoring-guide.md (new embedded)    │
   │  │  • Append Phase 36 closure section to Phase 34 deferred-items.md     │
   │  └──────────────────────────────────────────────────────────────────────┘

REQ-PORT-CLOSURE-04 (Plan 36-02, parallel in Wave 1)
   │
   │  ┌──────────────────────────────────────────────────────────────────────┐
   │  │  Plan 36-02: wiring.rs stripped-down port                            │
   │  │                                                                      │
   │  │  ┌─────────────────────┐  ┌─────────────────────┐                   │
   │  │  │ NEW FILE wiring.rs  │  │ Cargo.toml          │                   │
   │  │  │ ~300-400 LOC:       │  │ + serde_yaml_ng     │                   │
   │  │  │ • yaml_merge parser │  │   = "=0.10.0"       │                   │
   │  │  │ • yaml_merge applier│  └─────────────────────┘                   │
   │  │  │ • reversal failure  │           │                                 │
   │  │  │   test              │           │ used by                         │
   │  │  └─────────────────────┘           ↓                                 │
   │  │            │                ┌─────────────────────┐                  │
   │  │            │ wire into      │ wiring.rs           │                  │
   │  │            ↓                │ yaml_merge module   │                  │
   │  │  ┌─────────────────────┐    └─────────────────────┘                  │
   │  │  │ profile_cmd.rs      │                                             │
   │  │  │ cmd_profile_patch   │                                             │
   │  │  │ --yaml <overlay>    │                                             │
   │  │  │ handler             │                                             │
   │  │  └─────────────────────┘                                             │
   │  │                                                                      │
   │  │  EXCLUDED (deferred to v2.5-FU-3):                                   │
   │  │  • WriteFile / JsonMerge / JsonArrayAppend directives                │
   │  │  • SHA-256-keyed install records                                     │
   │  │  • Lockfile v3+v4 + idempotent reversal                              │
   │  │  • --force on `nono remove`                                          │
   │  └──────────────────────────────────────────────────────────────────────┘

REQ-PORT-CLOSURE-05 (Plan 36-03, parallel in Wave 1; 3 sequenced commits)
   │
   │  ┌──────────────────────────────────────────────────────────────────────┐
   │  │  Plan 36-03 Commit 1: b5f0a3ab diagnostic.rs restoration (D-20)      │
   │  │  • Restore 4 helpers in crates/nono/src/diagnostic.rs:               │
   │  │    - extract_path_after_syscall_word                                 │
   │  │    - infer_access_from_structured_syscall_line                       │
   │  │    - extract_structured_path_property                                │
   │  │    - extract_structured_string_property                              │
   │  │  • Wire into analyze_error_output (~line 215)                        │
   │  │  • Restore test_analyze_error_output_detects_node_eperm_mkdir_as_   │
   │  │    write                                                             │
   │  │  • Remove the 2 deferred-state comment blocks (lines 402-419 +       │
   │  │    2258-2267)                                                        │
   │  └──────────────────────────────────────────────────────────────────────┘
   │            │
   │            ↓ (Commit 2 layers on top of Commit 1's wiring)
   │  ┌──────────────────────────────────────────────────────────────────────┐
   │  │  Plan 36-03 Commit 2: b5f0a3ab surgical exec_strategy + helpers      │
   │  │                       (D-20)                                         │
   │  │  • crates/nono-cli/src/exec_strategy.rs (4148 LOC):                  │
   │  │    - ADD should_offer_profile_save() predicate                       │
   │  │    - ADD POST_EXIT_PTY_DRAIN_TIMEOUT const (250 → 100ms)             │
   │  │    - ADD new pre-profile-save callsite to existing                   │
   │  │      clear_signal_forwarding_target (DRIFT NOTE 3 — helper already   │
   │  │      exists at line 1987 with 2 callsites at 825 + 2047)             │
   │  │    - ADD startup-timeout machinery integration                       │
   │  │    - DO NOT MODIFY pub struct ExecConfig<'a> at line 276             │
   │  │  • crates/nono-cli/src/execution_runtime.rs (486 LOC):               │
   │  │    - ADD should_apply_startup_timeout() helper                       │
   │  │    - ADD startup_timeout_profile() helper                            │
   │  │    - ADD compute_executable_identity() helper                        │
   │  │    - ADD tests for startup-timeout interactive vs non-interactive    │
   │  │  • crates/nono-cli/src/cli.rs (4666 LOC):                            │
   │  │    - RESTORE LearnArgs.trace field at line ~2272 (verified absent;   │
   │  │      `\` typo at line 2272 in current state should ALSO be fixed —   │
   │  │      see DRIFT NOTE 4 below)                                         │
   │  │  • profile_save_runtime.rs, pty_proxy.rs, sandbox_log.rs,            │
   │  │    startup_prompt.rs: minor refinements per upstream b5f0a3ab        │
   │  └──────────────────────────────────────────────────────────────────────┘
   │            │
   │            ↓ (Commit 3 is the ONLY D-19 cherry-pick — bbdf7b85 applies   
   │              cleanly once Commit 1 has restored helpers + wiring)
   │  ┌──────────────────────────────────────────────────────────────────────┐
   │  │  Plan 36-03 Commit 3: bbdf7b85 escape-quote body rewrite (D-19)      │
   │  │  • crates/nono/src/diagnostic.rs:                                    │
   │  │    - Rewrite extract_structured_string_property body to handle       │
   │  │      escape-quoted characters                                        │
   │  │    - ADD test_analyze_error_output_detects_structured_node_eperm_   │
   │  │      mkdir_path                                                      │
   │  │    - ADD test_analyze_error_output_detects_structured_path_with_    │
   │  │      escaped_quote                                                   │
   │  │  • FULL 6-LINE D-19 trailer block citing bbdf7b85, lowercase 'a'     │
   │  │  • Smoke check at plan close:                                        │
   │  │    git log --format='%B' main~3..main | grep -c '^Upstream-commit:'  │
   │  │    MUST equal exactly 1                                              │
   │  └──────────────────────────────────────────────────────────────────────┘
```

### Recommended Project Structure (post-Phase-36 deltas only)

```
crates/nono-cli/src/
├── deprecated_schema.rs   # NEW (Plan 36-01a) — ~824 LOC verbatim port
├── wiring.rs              # NEW (Plan 36-02) — ~300-400 LOC, yaml_merge only
└── profile/mod.rs         # MUTATED (Plan 36-01b) — canonical sections added

crates/nono-cli/data/
├── policy.json            # MUTATED (Plan 36-01d) — built-in profile data
└── nono-profile.schema.json  # MUTATED (Plan 36-01d) — schema restructure

scripts/
├── test-list-aliases.sh   # NEW (Plan 36-01d) — alias inventory enforcement
└── lint-docs.sh           # NEW (Plan 36-01d) — docs alias-inventory check

docs/cli/
├── features/profiles-groups.mdx  # MUTATED (Plan 36-01d)
└── usage/flags.mdx               # MUTATED (Plan 36-01d)
```

### Pattern 1: D-19 cherry-pick trailer (verbatim 6-line shape — Plan 36-03 Commit 3 ONLY)
**What:** Mandatory commit-message trailer block for the one commit in Phase 36 that does a clean cherry-pick (bbdf7b85).
**When to use:** Plan 36-03 Commit 3 only. All other Phase 36 commits use D-20 manual-replay shape with design-source citations in the commit body, NO `Upstream-commit:` trailer.
**Example:**
```
fix(diagnostic): parse escaped quotes in structured properties

[body text describing what was ported]

Upstream-commit: bbdf7b85
Upstream-tag: v0.52.0
Upstream-author: Luke Hinds <lhinds@example.com>
Co-Authored-By: Luke Hinds <lhinds@example.com>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```
**Source:** `.planning/templates/upstream-sync-quick.md` § D-19 cherry-pick trailer block, lines 219-235.

### Pattern 2: D-20 manual-replay shape (Plans 36-01a/b/c/d, 36-02, 36-03 Commits 1+2)
**What:** Commit body cites upstream commit(s) as design-source ("This commit replays the design of upstream X without cherry-picking because…") with NO `Upstream-commit:` trailer.
**When to use:** Any Phase 36 commit where the upstream commit cannot apply cleanly because of structural fork divergence (e.g., upstream's wiring.rs doesn't exist in fork; fork's ExecConfig shape differs from upstream's; structural rewrites with no upstream cherry-pick path).
**Example:**
```
feat(36-02): port yaml_merge directive (stripped-down wiring.rs)

This commit creates fork-side crates/nono-cli/src/wiring.rs carrying ONLY the
yaml_merge directive machinery from upstream's v0.49.0 surface. Full upstream
wiring.rs (1761 LOC; WriteFile / JsonMerge / JsonArrayAppend / install records)
is explicitly excluded — fork's package system (package.rs + package_cmd.rs +
hooks.rs) is preserved per D-34-B1 + the "Hooks subsystem ownership" catalog
entry; full braiding deferred to v2.5-FU-3.

Design sources (D-20 manual replay):
- 242d4917 (upstream v0.49.0): serde_yaml_ng pin + reversal failure test
- 802c8566 (upstream v0.49.0): rustfmt (no-op for fork's shape)
- d44f5541 (upstream v0.49.0): yaml_merge directive (primary content)

Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

### Pattern 3: Atomic mechanical rename (Plan 36-01c — D-36-B4 invariant)
**What:** Single commit changes `override_deny` → `bypass_protection` across 17 files / 183 callsites.
**When to use:** Plan 36-01c only. The same `cargo build` + `cargo clippy --all-targets -- -D warnings -D clippy::unwrap_used` + `cargo test --workspace --all-features` gate runs at commit time guaranteeing rename consistency.
**Why atomic:** Reviewer sees one clean diff; rollback is one revert; matches Phase 33/34 atomic-cherry-pick discipline; no staged file-by-file mini-commits with type-alias scaffolding.

### Anti-Patterns to Avoid
- **String `starts_with()` on paths** — Plan 36-02 yaml_merge target-path validation MUST use `Path::components()` iteration, not `str::starts_with`. Triggers CLAUDE.md § Common Footguns #1. [CITED: CLAUDE.md § Path Handling]
- **`.unwrap()` or `.expect()`** — anywhere in Phase 36 code. Triggers `clippy::unwrap_used` gate. Use `?` propagation + `NonoError`. [CITED: CLAUDE.md § Coding Standards]
- **Single-line commit of the 183-callsite rename across multiple commits** — D-36-B4 explicitly forbids. Plan 36-01c MUST be atomic.
- **Modifying `pub struct ExecConfig<'a>` shape in Plan 36-03** — D-36-D1 explicitly forbids. The 17 fields stay verbatim; surgical port targets only function bodies + new helpers + new const + new test + new field on `LearnArgs` (NOT ExecConfig).
- **Touching `*_windows.rs` files in any Phase 36 plan** — D-36-A6 + D-34-E1 invariants. If a planner discovers a Windows-only touch is required, escalate via D-35-A1 inversion path (explicit decision row).
- **Adding audit-event hooks** — D-34-B2 surgical-retrofit posture inherited. No new audit emission for yaml_merge / profile-validate / env-filter outcomes in Phase 36.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| YAML parsing for yaml_merge directive | A custom YAML parser | `serde_yaml_ng` 0.10.0 (Plan 36-02) | Upstream's locked choice per `242d4917`; original `serde_yaml` unmaintained since 2024 |
| Per-process one-shot deprecation warning | New `OnceCell<()>` per legacy key | Mirror upstream's `DeprecationCounter` per-key `AtomicBool` shape (Plan 36-01a) | Upstream contract: one warning per legacy key per process. Plan 34-04b's existing `LEGACY_OVERRIDE_DENY_WARNED: AtomicBool` at profile/mod.rs:47 is the seed implementation; extend to per-key collection in deprecated_schema.rs |
| Legacy JSON key acceptance | `#[serde(rename = ...)]` only | `#[serde(alias = ...)]` + LegacyPolicyPatch rewriter (Plan 36-01a) | Upstream's pattern: serde alias accepts both keys; LegacyPolicyPatch normalizes post-parse so internal code sees only canonical names |
| Path validation in yaml_merge target | `str::starts_with` | `Path::components()` iteration (Plan 36-02) | CLAUDE.md § Common Footguns #1 — string `starts_with` is a known CVE-class footgun |
| Atomic file write for profile save | `std::fs::write` then `rename` | Existing `profile_save_runtime.rs` atomic primitives | Fork already has atomic-write helpers; Plan 36-03 Commit 2 minor refinements should reuse, not duplicate |
| Cross-platform exec-config field handling | New struct or extension layer | Keep fork's 17-field ExecConfig verbatim (D-36-D1) | Refactoring would regress Phase 18/26/27/31/34-08a/35-01 fork surfaces |

**Key insight:** Phase 36 is structurally a "verbatim port + surgical extension" phase, not a feature-design phase. Every "could we improve this while we're here?" temptation creates load-bearing fork surface and is explicitly rejected by D-34-B2 (inherited via CONTEXT.md). Plans should be near-mechanical translations of upstream patterns.

## Runtime State Inventory

Phase 36 is a rename/refactor phase (Plan 36-01c renames 183 callsites of `override_deny` → `bypass_protection`). Runtime state inventory:

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| **Stored data** | JSON profile files on user machines containing `override_deny` keys. | NONE — Plan 36-01a's `LegacyPolicyPatch` rewriter handles legacy keys at load time via `#[serde(alias = "bypass_protection")]` + rewrite-to-canonical-post-parse. Indefinite acceptance per D-36-B3; no migration date. Existing user profiles keep loading. |
| **Live service config** | Built-in profiles in `crates/nono-cli/data/policy.json` (1029 LOC) — already uses top-level `groups` shape (verified at policy.json:6 `"groups": { ... }`); partial alignment with target canonical sections. | Plan 36-01d: verify alignment with target canonical sections (`groups`, `commands.{allow,deny}`, `filesystem.{deny,bypass_protection}`); migrate any fork-specific shape to canonical form. Built-in profiles claude-code / codex / opencode / claude-no-keychain all need verification — likely none store under non-canonical keys but verify. |
| **OS-registered state** | None — Phase 36 does NOT change any service registration, Windows scheduled task descriptions, pm2 process names, or systemd unit names. The Phase 25 RESL backends + Phase 31 broker process names are unaffected. | None. |
| **Secrets and env vars** | None — Phase 36 does NOT rename any SOPS keys, .env file vars, or CI environment variables. `allowed_env_vars` / `denied_env_vars` field names stay verbatim (no field rename, no env-var-name change). | None. |
| **Build artifacts / installed packages** | `target/` may contain stale incremental compilation artifacts after the 183-callsite rename. | Plan 36-01c executor should run `cargo clean -p nono-cli` before the rename commit to guarantee clean recompile. (Standard hygiene, not a hard requirement.) |

**The canonical question — *After every file in the repo is updated, what runtime systems still have the old string cached, stored, or registered?*** — answer: **user-profile JSON files**, handled by `LegacyPolicyPatch` indefinite-acceptance per D-36-B3. No other runtime state carries the `override_deny` string.

## Common Pitfalls

### Pitfall 1: Confusing `policy_cmd.rs` references in CONTEXT.md / deferred-items.md / profile/mod.rs comments
**What goes wrong:** Plan 36-01c executor reads "210-callsite rename across 14+ files including policy_cmd.rs" and tries to find `crates/nono-cli/src/policy_cmd.rs` — it doesn't exist.
**Why it happens:** Upstream has `policy_cmd.rs` as a separate module; fork merged its logic into `profile_cmd.rs` + `policy.rs`. CONTEXT.md and the profile/mod.rs comment at line 430 carry forward the upstream file list verbatim.
**How to avoid:** Planner explicitly lists fork's 17 actual files in Plan 36-01c PLAN.md (NOT the upstream 14-file list). The verified list is in this RESEARCH.md's System Architecture Diagram (Plan 36-01c block).
**Warning signs:** Executor reports "file not found: crates/nono-cli/src/policy_cmd.rs" during the rename pass.

### Pitfall 2: `clear_signal_forwarding_target` re-introduction
**What goes wrong:** Plan 36-03 Commit 2 executor reads "restore `clear_signal_forwarding_target()` call before profile-save prompt" (D-36-D1 task list) and tries to introduce the function as new.
**Why it happens:** D-36-D1 task wording sounds like the function is missing; in fact only the new pre-profile-save callsite is missing. Function exists at exec_strategy.rs:1987 with 2 existing callsites at lines 825 + 2047.
**How to avoid:** Plan 36-03 Commit 2 task must read "add NEW callsite to existing `clear_signal_forwarding_target()` immediately before the profile-save prompt." NOT "restore the helper."
**Warning signs:** Compile error `cannot find function clear_signal_forwarding_target` when there should be a duplicate-definition error.

### Pitfall 3: cli.rs line 2272 typo confounding LearnArgs.trace restoration
**What goes wrong:** When restoring `LearnArgs.trace` per D-36-D1, executor finds an existing syntax-ambiguous line at cli.rs:2272 (`\ Timeout in seconds (default: run until command exits)` — backslash-doc-comment typo) and might misinterpret the structure of `LearnArgs`.
**Why it happens:** Plan 34-08b removed `LearnArgs.trace` but left a stray backslash in place of `///` for the next field's doc comment. This compiles via Rust's tolerant lexer but reads oddly.
**How to avoid:** Plan 36-03 Commit 2 fixes the `\ ` → `/// ` typo at cli.rs:2272 alongside the `LearnArgs.trace` restoration. Both are tiny inline edits.
**Warning signs:** rustfmt or clippy may flag the `\ ` line (verify against current clippy clean state).

### Pitfall 4: PTY-quiet-period 250→100ms regression on Phase 17 attach-streaming or Phase 31 broker ConPTY
**What goes wrong:** Plan 36-03 Commit 2's `POST_EXIT_PTY_DRAIN_TIMEOUT 250 → 100ms` change reduces the time the PTY engine waits for child output before tearing down the pipe. On slow CI hosts or under heavy load, the shorter window may surface flakes in:
- `crates/nono-cli/tests/attach_streaming_integration.rs` (Phase 17 attach-streaming surface; verified to exist via Glob).
- Phase 31 broker ConPTY path in `crates/nono-shell-broker/src/main.rs` (verified to exist via Glob); Windows `CreateProcessAsUserW(EXTENDED_STARTUPINFO_PRESENT)` Low-IL child spawn path.
**Why it happens:** Faster timeout pulls forward post-exit drain race; existing tests may rely on the 250ms wall to mask their own timing assumptions.
**How to avoid:** Plan 36-03 close gate step 6 (Phase 15 5-row detached-console smoke gate) MUST pass; if attach-streaming or broker ConPTY surfaces a flake, the plan blocks per D-36-D3 — investigate; compromise to 150ms if needed; do NOT just disable the new timing.
**Warning signs:** `cargo test --workspace --all-features` reports flaky attach_streaming_integration failures, OR Phase 15 smoke gate (close-gate step 6) intermittently fails attach/detach round-trip. v2.5-FU-6 deferral is the compromise-formalization path.

### Pitfall 5: Wave 1 plan execution accidentally landing the 36-01a callsite-rename foundation BEFORE 36-01b canonical sections
**What goes wrong:** Plan 36-01a creates `deprecated_schema.rs` with `LegacyPolicyPatch`; the rewriter needs to know about canonical Profile sections in order to rewrite legacy keys correctly. If 36-01c (rename) lands before 36-01b (canonical sections), the LegacyPolicyPatch rewriter has nothing to rewrite TO.
**Why it happens:** Wave 1 parallel execution may tempt overlapping with Wave 2 36-01b/c/d if executor is impatient. D-36-A2 strict ordering: 36-01b → 36-01c → 36-01d.
**How to avoid:** Plan 36-01a PLAN.md "Depends on:" line empty (foundation plan); Plan 36-01b "Depends on: 36-01a"; Plan 36-01c "Depends on: 36-01b"; Plan 36-01d "Depends on: 36-01c". Planner enforces sequencing; executor reads "Depends on:" before starting.
**Warning signs:** Test failures in deprecated_schema unit tests because the canonical sections don't exist yet to rewrite into.

### Pitfall 6: Plan 36-02 yaml_merge target-path validation skipping canonicalization
**What goes wrong:** A profile with `yaml_merge: { target: "../../../etc/passwd" }` could escape the profile directory if Plan 36-02's target-path validation uses string ops instead of `Path::components()` iteration + canonicalization.
**Why it happens:** Upstream's `d44f5541` pattern may use simpler validation that the fork's `validate_path_within` defense-in-depth retention catalog entry forbids removing.
**How to avoid:** Plan 36-02 MUST preserve fork's `validate_path_within` callsites where they intersect yaml_merge target paths. Path component comparison + canonicalization at the validation boundary. CLAUDE.md § Common Footguns #1.
**Warning signs:** PR reviewer flags `str::starts_with(target_path, profile_dir)` shape; existing `validate_path_within` callsites in `profile_cmd.rs` are silently deleted instead of extended.

### Pitfall 7: Plan 36-01c missing the policy.json fixture rename
**What goes wrong:** Plan 36-01c renames 183 `override_deny` callsites in `.rs` files but forgets the JSON schema fixtures in `crates/nono-cli/tests/fixtures/` and `crates/nono-cli/data/policy.json` (verified to use `groups` top-level but has no current `override_deny` keys — verify via grep).
**Why it happens:** Atomic-commit discipline (D-36-B4) focuses attention on Rust files; data/test-fixture files don't show up in `grep "override_deny" --include="*.rs"`.
**How to avoid:** Plan 36-01c rename pass uses `grep -rn "override_deny" .` (no `--include` filter) to catch JSON/YAML/MD fixtures. CONTEXT.md line 174 explicitly lists `JSON schema fixtures` in the rename target list.
**Warning signs:** Schema validation tests fail after the rename because the schema fixture still references `override_deny`.

## Code Examples

### Pattern 1: Legacy serde-alias acceptance (already present in fork; extend per Plan 36-01a)

```rust
// Source: crates/nono-cli/src/profile/mod.rs:439-440 (current fork state)
#[serde(default, alias = "bypass_protection")]
pub override_deny: Vec<String>,
```

After Plan 36-01c (canonical rename):

```rust
// Target post-rename shape (verbatim from upstream f0abd413 + canonical sections)
#[serde(default, alias = "override_deny")]
pub bypass_protection: Vec<String>,
```

### Pattern 2: Per-key DeprecationCounter (Plan 36-01a target shape, extending fork's seed)

```rust
// Current fork seed (profile/mod.rs:47):
static LEGACY_OVERRIDE_DENY_WARNED: AtomicBool = AtomicBool::new(false);

// Plan 36-01a target shape in NEW FILE deprecated_schema.rs:
use std::sync::atomic::{AtomicBool, Ordering};

pub struct DeprecationCounter {
    // One AtomicBool per legacy key tracked
    keys: std::sync::OnceLock<HashMap<&'static str, AtomicBool>>,
}

impl DeprecationCounter {
    pub fn emit_once(&self, key: &'static str, canonical: &'static str) {
        let map = self.keys.get_or_init(|| { /* lazy init known legacy keys */ });
        if let Some(flag) = map.get(key) {
            if !flag.swap(true, Ordering::SeqCst) {
                eprintln!(
                    "WARN: profile field `{key}` is deprecated; use `{canonical}` instead"
                );
            }
        }
    }
}
```
**Source:** Upstream `f0abd413` `deprecated_schema::DeprecationCounter` pattern — verified via deferred-items.md § P34-DEFER-04b-1 description.

### Pattern 3: D-19 trailer for Plan 36-03 Commit 3 (verbatim)

```
Upstream-commit: bbdf7b85
Upstream-tag: v0.52.0
Upstream-author: Luke Hinds <lhinds@example.com>
Co-Authored-By: Luke Hinds <lhinds@example.com>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```
**Source:** `.planning/templates/upstream-sync-quick.md` § D-19 cherry-pick trailer block lines 219-235; lowercase 'a' in `Upstream-author` is mandatory per D-34-E2 field rules.

### Pattern 4: ExecConfig field preservation invariant (D-36-D1)

```rust
// crates/nono-cli/src/exec_strategy.rs:276 — DO NOT MODIFY in Plan 36-03
pub struct ExecConfig<'a> {
    pub command: &'a [String],
    pub resolved_program: &'a std::path::Path,
    pub caps: &'a CapabilitySet,
    pub env_vars: Vec<(&'a str, &'a str)>,
    pub cap_file: Option<&'a std::path::Path>,
    pub current_dir: &'a std::path::Path,
    pub no_diagnostics: bool,
    pub threading: ThreadingContext,
    pub protected_paths: &'a [std::path::PathBuf],
    pub profile_save_base: Option<&'a str>,
    pub startup_timeout: Option<StartupTimeoutConfig<'a>>,
    pub capability_elevation: bool,            // cfg-gated Linux
    #[cfg(target_os = "linux")]
    pub seccomp_proxy_fallback: bool,
    pub allowed_env_vars: Option<Vec<String>>,
    pub denied_env_vars: Option<Vec<String>>,
}
```

Note: CONTEXT.md D-36-D1 enumerates 11 fork-side ExecConfig fields, including some that this verification did not find as separate fields (e.g., `resource_limits`, `audit_signer`, `bypass_protection_paths`). Those fields likely live on other structs (`ExecutionFlags`, `SupervisedRuntimeContext`, `LaunchPlan`) and pass through to ExecConfig at construction time. **Recommendation:** Plan 36-03 Commit 2 explicitly enumerates the 17 ExecConfig fields it observes and confirms none are removed. The D-36-D1 invariant is "preserve the shape," not "preserve a specific enumeration."

## Project Constraints (from CLAUDE.md)

Extracted from `./CLAUDE.md` — Phase 36 plans MUST honor these:

- **No `.unwrap()` or `.expect()`** — strictly forbidden; enforced by `clippy::unwrap_used`. Exceptions in `#[cfg(test)]` modules and `no_run` doc examples only. Use `Result<T>` + `?` propagation.
- **No `#[allow(dead_code)]`** — avoid lazy use; remove unused code or write tests. (Plan 36-01a `LegacyPolicyPatch` helpers must be reachable from `analyze` callers, otherwise gate them appropriately.)
- **DCO sign-off** — all commits must include `Signed-off-by:` line. Plan 36-03 Commit 3's D-19 trailer block carries TWO `Signed-off-by:` lines (full name + GitHub handle) per template.
- **Env var save/restore in tests** — tests that modify `HOME`, `TMPDIR`, `XDG_CONFIG_HOME`, `NONO_TEST_HOME` must save/restore the original. Critical for Plan 36-01a/b tests that exercise legacy vs canonical profile loading.
- **Path component comparison** — never use `str::starts_with` on paths. Use `Path::components()` iteration. Critical for Plan 36-02 yaml_merge target-path validation.
- **Path canonicalization at enforcement boundary** — canonicalize before validation. TOCTOU race window awareness.
- **`#[must_use]` on critical Results** — Plan 36-01a `LegacyPolicyPatch::rewrite()` return value should carry `#[must_use]`.
- **Cross-target clippy** — `--target x86_64-unknown-linux-gnu` + `--target x86_64-apple-darwin` clippy gates required for cross-platform code (most of Phase 36). D-36-A5 close-gate steps 3 + 4.
- **Library should almost never panic** — Plan 36-01a (in nono-cli, not nono library) and Plan 36-03 Commits 1+3 (touches nono library at `crates/nono/src/diagnostic.rs`) must use `Result<T>` instead of panic for expected error conditions.
- **macOS Seatbelt profile string escaping** — relevant for Plan 36-03 macOS-gated learn-diagnostic output (b5f0a3ab introduces macOS `print_macos_run_guidance` per absorbed Plan 34-08b state).
- **Windows path forms (UNC, `\\?\`, drive-letter)** — handled by existing `strip_verbatim_prefix` helper (Phase 35 Plan 35-03 surface); Plan 36-02 yaml_merge target-path validation must compose with this primitive.

## Per-Plan Implementation Approach

### Plan 36-01a — deprecated_schema module foundation

**Technical approach:**
1. Create `crates/nono-cli/src/deprecated_schema.rs` as a new file.
2. Port upstream `f0abd413`'s `deprecated_schema` module wholesale (~824 LOC):
   - `LegacyPolicyPatch` struct with `Deserialize` impl that captures legacy keys (`override_deny`, others if upstream's `f0abd413` carries additional aliases) and a `rewrite()` method that returns canonical form.
   - `DeprecationCounter` struct with per-key `AtomicBool` collection; `emit_once(key, canonical_key)` API.
   - `--strict` mode lever (likely a `bool` field threaded through profile-load options).
3. Register module via `mod deprecated_schema;` in `crates/nono-cli/src/main.rs`.
4. Add `--strict` flag to `ProfileValidateArgs` in `crates/nono-cli/src/cli.rs`.
5. Wire `LegacyPolicyPatch` rewriter + `DeprecationCounter` into profile-load pipeline in `crates/nono-cli/src/profile_cmd.rs` (per `cmd_profile_validate` and `cmd_profile_show` handlers).
6. Add round-trip test: legacy JSON → load → re-serialize → compare to canonical form (planner discretion per CONTEXT.md, recommended yes).
7. Add `--strict` fail-closed test: legacy key + `--strict` flag → non-zero exit + clear error.

**Key files to touch:**
- NEW: `crates/nono-cli/src/deprecated_schema.rs` (~824 LOC)
- MUTATE: `crates/nono-cli/src/main.rs` (+1 line: `mod deprecated_schema;`)
- MUTATE: `crates/nono-cli/src/cli.rs` (4666 LOC; +1 `--strict` flag in `ProfileValidateArgs`)
- MUTATE: `crates/nono-cli/src/profile_cmd.rs` (3063 LOC; wire LegacyPolicyPatch into load path)
- KEEP AS-IS: `crates/nono-cli/src/profile/mod.rs:47` AtomicBool seed implementation (Plan 36-01a extends, doesn't replace)
- KEEP AS-IS: `crates/nono-cli/src/deprecated_policy.rs` (different concern — CLI alias shim)

**Risks/landmines:**
- The existing AtomicBool at `profile/mod.rs:47` (LEGACY_OVERRIDE_DENY_WARNED) may conflict with the new DeprecationCounter shape. Planner must decide: keep both (additive), retire old (replace), or migrate old into new (refactor). Recommend: migrate `LEGACY_OVERRIDE_DENY_WARNED` into the new `DeprecationCounter` map as the key `"override_deny"`'s `AtomicBool`. Delete the old global.
- `--strict` flag wiring must compose with existing `nono profile validate` flag set in `cli.rs` (lines around 1359-1370 currently carry the `bypass_protection` clap visible_alias; verify no flag-name collision).

**Recommended task ordering inside the plan:**
1. Task 1: Create `deprecated_schema.rs` with `LegacyPolicyPatch` + `DeprecationCounter` types (no wiring yet, all unit tests inline).
2. Task 2: Register module + add `--strict` clap flag.
3. Task 3: Wire `LegacyPolicyPatch` rewriter into profile-load path in `profile_cmd.rs`.
4. Task 4: Migrate old `LEGACY_OVERRIDE_DENY_WARNED` AtomicBool into `DeprecationCounter`; delete the global.
5. Task 5: Add round-trip + `--strict` fail-closed tests.
6. Task 6: Close-gate verification (all 8 steps).
7. Task 7: D-20 commit body citing `f0abd413` design source.

### Plan 36-01b — canonical Profile sections

**Technical approach:**
Restructure the `Profile` / `LoadedProfile` structs in `crates/nono-cli/src/profile/mod.rs` (6140 LOC) to expose canonical sections per upstream `f0abd413`:
- `groups: HashMap<String, GroupConfig>` (currently lives in `policy.json` data file; verify if also struct-level).
- `commands: CommandsConfig` with `allow: Vec<String>` + `deny: Vec<String>` sub-fields.
- `filesystem: FilesystemConfig` extended with `deny: Vec<String>` + `bypass_protection: Vec<String>` (currently has `allow`, `read`, `write`, `allow_file`, `read_file`, `write_file` — see profile/mod.rs:205-224).

**Key files to touch:**
- MUTATE: `crates/nono-cli/src/profile/mod.rs` (6140 LOC; restructure Profile/LoadedProfile + FilesystemConfig + new CommandsConfig + new GroupsConfig)
- VERIFY (do NOT mutate library): `crates/nono/src/capability.rs::CapabilitySet` — must still compose with restructured Profile sections.

**Risks/landmines:**
- The `From<ProfileDeserialize> for Profile` impl at profile/mod.rs:1642 enumerates 18 fields; canonical sections add 2-3 more. Verify exhaustive `From` impl after restructure.
- Phase 35 Plan 35-03 landed JSON Map-emission omit-when-None for Option<...> security fields. Plan 36-01b canonical sections must preserve this shape (nest cleanly within Map).
- `policy.json` already uses top-level `groups` shape (verified at policy.json:6). Struct field shape must match the JSON data shape.

**Recommended task ordering inside the plan:**
1. Task 1: Define new `CommandsConfig`, `GroupsConfig` types.
2. Task 2: Extend `FilesystemConfig` with `deny` + `bypass_protection` fields.
3. Task 3: Add canonical-section fields to `Profile` + `ProfileDeserialize`.
4. Task 4: Update `From<ProfileDeserialize>` impl.
5. Task 5: Verify `CapabilitySet` composition still works (smoke test).
6. Task 6: Close-gate.

### Plan 36-01c — 183-callsite override_deny → bypass_protection rename

**Technical approach:**
Single atomic commit (D-36-B4) renaming `override_deny` → `bypass_protection` across 17 files / 183 callsites. Mechanical sed/IDE rename; rely on Rust's type system + `cargo build` + `cargo clippy --all-targets -- -D warnings -D clippy::unwrap_used` + `cargo test --workspace --all-features` to verify consistency.

**Key files to touch (verified counts via grep):**
| File | Callsite count |
|------|----------------|
| `crates/nono-cli/src/profile/mod.rs` | 66 |
| `crates/nono-cli/src/profile_save_runtime.rs` | 23 |
| `crates/nono-cli/src/capability_ext.rs` | 23 |
| `crates/nono-cli/src/cli.rs` | 14 |
| `crates/nono-cli/src/profile_cmd.rs` | 13 |
| `crates/nono-cli/src/profile_runtime.rs` | 9 |
| `crates/nono-cli/src/sandbox_state.rs` | 8 |
| `crates/nono-cli/src/learn.rs` | 6 |
| `crates/nono-cli/src/policy.rs` | 6 |
| `crates/nono-cli/src/profile/builtin.rs` | 6 |
| `crates/nono-cli/src/command_runtime.rs` | 4 |
| `crates/nono-cli/src/query_ext.rs` | 4 |
| `crates/nono-cli/src/sandbox_prepare.rs` | 4 |
| `crates/nono-cli/src/execution_runtime.rs` | 3 |
| `crates/nono-cli/src/launch_runtime.rs` | 3 |
| `crates/nono-cli/src/main.rs` | 2 |
| `crates/nono-cli/src/why_runtime.rs` | 2 |
| **Total** | **196** (raw grep count; some hits are doc-comment refs that may not need rename — verify each) |

Plus test fixtures and JSON files (verify via `grep -rn "override_deny" crates/nono-cli/tests/fixtures/ crates/nono-cli/data/`).

**Risks/landmines:**
- **`policy_cmd.rs` does NOT exist in fork** — CONTEXT.md / deferred-items.md mention it; the file does not. Skip.
- Doc-comment references in profile/mod.rs (lines 23, 29, 30) are not callsites; verify whether to keep historic or rename for consistency.
- The clap `visible_alias = "bypass-protection"` at cli.rs:1364 + :1723 may need to flip: the canonical flag becomes `--bypass-protection` and the legacy `--override-deny` becomes the visible_alias. Verify direction of rename.

**Recommended task ordering inside the plan:**
1. Task 1: Pre-flight: `cargo clean -p nono-cli` (clear stale incremental artifacts).
2. Task 2: Atomic rename via sed/IDE across all 17 files. Single commit.
3. Task 3 (in the SAME commit): Update doc-comments that reference the old name.
4. Task 4: Verify JSON test fixtures + `crates/nono-cli/data/policy.json` (likely no rename needed since policy.json already uses canonical `groups`).
5. Task 5: `cargo build --workspace --all-features` + `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` + `cargo test --workspace --all-features` — all green before commit lands.
6. Task 6: Close-gate.

### Plan 36-01d — data + docs + tooling

**Technical approach:**
1. Migrate built-in profile data in `crates/nono-cli/data/policy.json` (1029 LOC; already uses top-level `groups` — verify the 4 built-in profiles claude-code/codex/opencode/claude-no-keychain align with canonical sections).
2. Restructure JSON schema fixture `crates/nono-cli/data/nono-profile.schema.json` (637 LOC).
3. Create `scripts/test-list-aliases.sh` (alias inventory enforcement).
4. Create `scripts/lint-docs.sh` (docs alias-inventory check).
5. Verify `scripts/regenerate-schema.sh` produces canonical-form output.
6. Migrate `docs/cli/features/profiles-groups.mdx` (already exists; restructure).
7. Migrate `docs/cli/usage/flags.mdx` (already exists; update for canonical flag names).
8. Embed profile-authoring guide in `crates/nono-cli/data/profile-authoring-guide.md`.
9. Append "Phase 36 closure" section to `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md` flipping P34-DEFER-04b-1, 06-1, 08b-1, 08b-2, 09-2 from open to closed-by-Phase-36 (per CONTEXT.md "Plan SUMMARY" guidance).

**Key files to touch:**
- MUTATE: `crates/nono-cli/data/policy.json` (1029 LOC).
- MUTATE: `crates/nono-cli/data/nono-profile.schema.json` (637 LOC).
- NEW: `scripts/test-list-aliases.sh`.
- NEW: `scripts/lint-docs.sh`.
- VERIFY (existing): `scripts/regenerate-schema.sh`.
- MUTATE: `docs/cli/features/profiles-groups.mdx`.
- MUTATE: `docs/cli/usage/flags.mdx`.
- NEW: `crates/nono-cli/data/profile-authoring-guide.md`.
- MUTATE: `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md` (append closure section).

**Risks/landmines:**
- `policy.json` ALREADY uses upstream-canonical `groups` shape — partial alignment with target. Verify the 4 built-in profiles' commands.{allow,deny} + filesystem.{deny,bypass_protection} sections vs. current shape.
- Schema-regenerate must run reproducibly on Windows host; verify `scripts/regenerate-schema.sh` is shell-compatible or has a `.ps1` variant.

**Recommended task ordering inside the plan:**
1. Task 1: Audit built-in profile data alignment (groups already done; verify commands + filesystem sections).
2. Task 2: Migrate built-in profile data.
3. Task 3: Restructure JSON schema fixture.
4. Task 4: Verify `regenerate-schema.sh` reproducibility.
5. Task 5: Create `test-list-aliases.sh` + `lint-docs.sh`.
6. Task 6: Migrate docs.
7. Task 7: Embed profile-authoring guide.
8. Task 8: Append closure section to Phase 34 deferred-items.md.
9. Task 9: Close-gate.

### Plan 36-02 — wiring.rs stripped-down port (yaml_merge only)

**Technical approach:**
1. Create `crates/nono-cli/src/wiring.rs` carrying ONLY the yaml_merge directive parser + applier from upstream `d44f5541`.
2. Pin `serde_yaml_ng = "=0.10.0"` in `crates/nono-cli/Cargo.toml [dependencies]` block (from upstream `242d4917`).
3. Add the reversal failure test (from upstream `242d4917`).
4. Register module via `mod wiring;` in `crates/nono-cli/src/main.rs`.
5. Wire `yaml_merge` directive into `nono profile patch --yaml <overlay>` handler in `crates/nono-cli/src/profile_cmd.rs`.
6. Preserve `validate_path_within` callsites where they intersect yaml_merge target paths (defense-in-depth catalog entry).

**Key files to touch:**
- NEW: `crates/nono-cli/src/wiring.rs` (~300-400 LOC).
- MUTATE: `crates/nono-cli/Cargo.toml` (+1 dep line for `serde_yaml_ng = "=0.10.0"`).
- MUTATE: `crates/nono-cli/src/main.rs` (+1 line: `mod wiring;`).
- MUTATE: `crates/nono-cli/src/profile_cmd.rs` (3063 LOC; wire directive into `--yaml` handler).

**Risks/landmines:**
- Acceptance criterion #1 ("idempotent JSON-merge install records") EXPLICITLY scope-trimmed to v2.5-FU-3. Plan 36-02 PLAN.md `Acceptance:` section MUST mark #1 as "intentionally not satisfied in v2.4" with citation to D-36-C1 + v2.5-FU-3 deferral.
- D-20 manual-replay shape: single combined commit citing 3 upstream commits as design-source. NO D-19 trailer (upstream's commits modified upstream-only `wiring.rs` which doesn't exist in fork; cherry-pick was structurally infeasible).
- `serde_yaml_ng` 0.10.0 availability on crates.io — recommend executor `cargo search serde_yaml_ng` before commit.
- `validate_path_within` defense-in-depth (catalog entry in `.planning/templates/upstream-sync-quick.md` § Fork-divergence catalog) must NOT be silently removed during yaml_merge wiring.

**Recommended task ordering inside the plan:**
1. Task 1: Verify `serde_yaml_ng` 0.10.0 on crates.io.
2. Task 2: Pin dep in Cargo.toml + `cargo build` to confirm resolution.
3. Task 3: Create `wiring.rs` with yaml_merge parser + applier (verbatim port from `d44f5541`, adapted to fork's profile-patch idioms).
4. Task 4: Add reversal failure test from `242d4917`.
5. Task 5: Register module + wire into `profile_cmd.rs` `--yaml` handler.
6. Task 6: Verify `validate_path_within` callsites preserved.
7. Task 7: Path validation tests: target-path escape via `../../../`, UNC alias attempts, symlink escapes — all must be rejected.
8. Task 8: Close-gate.
9. Task 9: Single combined D-20 commit body citing `242d4917`, `802c8566`, `d44f5541`.

### Plan 36-03 — b5f0a3ab surgical + bbdf7b85 escape-quote tail

**Technical approach:** Three sequenced commits in a single PLAN.md / single PR.

**Commit 1 (D-20 manual-replay, b5f0a3ab surgical diagnostic.rs restoration):**
1. Open `crates/nono/src/diagnostic.rs` (3368 LOC).
2. Restore 4 helpers (where they would be in upstream's structure):
   - `extract_path_after_syscall_word`
   - `infer_access_from_structured_syscall_line`
   - `extract_structured_path_property`
   - `extract_structured_string_property`
3. Wire all 4 into `analyze_error_output` at ~line 215.
4. Restore `test_analyze_error_output_detects_node_eperm_mkdir_as_write` test.
5. Remove the 2 deferred-state comment blocks at lines 402-419 + 2258-2267.
6. Commit body cites `b5f0a3ab` as design source.

**Commit 2 (D-20 manual-replay, b5f0a3ab surgical exec_strategy + helpers):**
1. `crates/nono-cli/src/exec_strategy.rs` (4148 LOC):
   - ADD `should_offer_profile_save()` predicate. (Currently NOT present — verified.)
   - ADD `POST_EXIT_PTY_DRAIN_TIMEOUT` const at module scope (250 → 100ms, citing CONTEXT.md D-36-D3 regression-coverage constraint).
   - ADD new pre-profile-save callsite to existing `clear_signal_forwarding_target()` (DRIFT NOTE 3: helper exists at line 1987; this is a new callsite, not a function restoration).
   - ADD startup-timeout machinery integration.
   - DO NOT modify `pub struct ExecConfig<'a>` at line 276 (D-36-D1 invariant).
2. `crates/nono-cli/src/execution_runtime.rs` (486 LOC):
   - ADD `should_apply_startup_timeout()` helper. (Currently NOT present — verified.)
   - ADD `startup_timeout_profile()` helper.
   - ADD `compute_executable_identity()` helper.
   - ADD tests for startup-timeout interactive vs non-interactive arms.
3. `crates/nono-cli/src/cli.rs` (4666 LOC):
   - RESTORE `LearnArgs.trace` field (verified absent at LearnArgs struct lines 2263-2295).
   - FIX `\ ` → `/// ` typo at line 2272 (DRIFT NOTE 4: pre-existing typo from Plan 34-08b removal).
4. Minor refinements per upstream `b5f0a3ab`: `profile_save_runtime.rs`, `pty_proxy.rs`, `sandbox_log.rs`, `startup_prompt.rs`.
5. Verify Phase 17 attach-streaming (`crates/nono-cli/tests/attach_streaming_integration.rs`) + Phase 31 broker ConPTY (`crates/nono-shell-broker/src/main.rs`) regression coverage.
6. Verify Phase 10 / D-02 Windows admin gate in `learn_runtime.rs` (Plan 34-08b's `print_macos_run_guidance` absorption) not regressed.
7. Commit body cites `b5f0a3ab` as design source.

**Commit 3 (D-19 cherry-pick, bbdf7b85 escape-quote body rewrite):**
1. `crates/nono/src/diagnostic.rs`:
   - Rewrite `extract_structured_string_property` body to handle escape-quoted characters (per upstream `bbdf7b85`).
   - ADD `test_analyze_error_output_detects_structured_node_eperm_mkdir_path`.
   - ADD `test_analyze_error_output_detects_structured_path_with_escaped_quote`.
2. Full 6-line D-19 trailer block citing `bbdf7b85` (lowercase 'a' in `Upstream-author`).

**Smoke check at plan close (per D-36-D2):**
```
git log --format='%B' main~3..main | grep -c '^Upstream-commit: '
# MUST equal exactly 1 (only Commit 3 carries the D-19 trailer)
```

**Key files to touch:**
- MUTATE: `crates/nono/src/diagnostic.rs` (3368 LOC; Commits 1 + 3).
- MUTATE: `crates/nono-cli/src/exec_strategy.rs` (4148 LOC; Commit 2; do NOT touch ExecConfig struct).
- MUTATE: `crates/nono-cli/src/execution_runtime.rs` (486 LOC; Commit 2).
- MUTATE: `crates/nono-cli/src/cli.rs` (4666 LOC; Commit 2; restore `LearnArgs.trace`).
- MUTATE: `crates/nono-cli/src/profile_save_runtime.rs`, `pty_proxy.rs`, `sandbox_log.rs`, `startup_prompt.rs` (Commit 2; minor refinements).

**Risks/landmines:**
- **PTY-quiet-period 250→100ms regression** on Phase 17 attach-streaming or Phase 31 broker ConPTY — Pitfall 4 above. v2.5-FU-6 deferral is the compromise-formalization path if a parametric proptest becomes necessary.
- **`clear_signal_forwarding_target` is NOT new** — DRIFT NOTE 3 above; existing helper at line 1987.
- **`LearnArgs.trace` restoration + typo fix at cli.rs:2272** must both land in Commit 2.
- **macOS clippy gate (close-gate step 4) is load-bearing** — `b5f0a3ab` introduces macOS-gated code paths (`print_macos_run_guidance` + macOS learn diagnostics). Verify `cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` is green.

**Recommended task ordering inside the plan:**
1. Task 1 (Commit 1): Restore 4 diagnostic helpers + wire into `analyze_error_output` + restore 1 test + remove 2 deferred-state comment blocks.
2. Task 2 (Commit 2): Add `should_offer_profile_save`, `POST_EXIT_PTY_DRAIN_TIMEOUT`, startup-timeout machinery, new `clear_signal_forwarding_target` callsite. Add `should_apply_startup_timeout`, `startup_timeout_profile`, `compute_executable_identity` helpers + tests. Restore `LearnArgs.trace`; fix line 2272 typo. Minor refinements to 4 sibling files.
3. Task 3 (Commit 3): bbdf7b85 escape-quote body rewrite + 2 tests; full D-19 trailer.
4. Task 4: Phase 17 attach-streaming regression coverage (`cargo test --workspace --all-features` includes `attach_streaming_integration`).
5. Task 5: Phase 31 broker ConPTY smoke gate (close-gate step 6: 5-row detached-console flow).
6. Task 6: Plan-close smoke check (`grep -c '^Upstream-commit: '` equals 1).
7. Task 7: Cross-target clippy (Linux + macOS) + close-gate.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `serde_yaml` (Original Sin) | `serde_yaml_ng` 0.10.0 | upstream `242d4917`, 2026-05-07 | `serde_yaml` deprecated/unmaintained since 2024; `serde_yaml_ng` is the community fork. Plan 36-02 must pin to 0.10.0 to lock the surface against breaking changes |
| Plan 34-04b Option C rename-acceptance (serde alias + clap visible_alias + AtomicBool one-time stderr warn) | Full Option C verbatim port (LegacyPolicyPatch rewriter + per-key DeprecationCounter + `--strict` mode + canonical sections) | Phase 36 (D-36-B1) | Replaces pragmatic scaffolding with full upstream surface; future deferral absorptions pick up canonical form for free |
| `extract_path_after_syscall_word` + 3 sibling helpers DEFERRED (Plan 34-08b commit 4/5 scope-trim) | Restored + wired into `analyze_error_output` | Phase 36 Plan 36-03 Commit 1 | Diagnostic engine regains structured-property parsing pipeline; bbdf7b85 escape-quote tail applies cleanly post-restoration |
| `POST_EXIT_PTY_DRAIN_TIMEOUT` 250ms (current fork) | `POST_EXIT_PTY_DRAIN_TIMEOUT` 100ms (upstream b5f0a3ab) | Phase 36 Plan 36-03 Commit 2 | Faster PTY drain after child exit; must not regress Phase 17 attach-streaming or Phase 31 broker ConPTY (D-36-D3 explicit regression coverage) |

**Deprecated/outdated:**
- The pragmatic Plan 34-04b Option C scaffolding (`profile/mod.rs:47` `LEGACY_OVERRIDE_DENY_WARNED: AtomicBool` + serde alias + clap visible_alias) is replaced by Plan 36-01a's verbatim port — but the AtomicBool seed implementation migrates into the new `DeprecationCounter` map. Don't delete prematurely; refactor in-place.
- Fork's flat `Profile` shape (no canonical `groups` / `commands.*` / `filesystem.*` sections) is replaced by Plan 36-01b. Built-in profile data at `crates/nono-cli/data/policy.json` already uses partial canonical form (top-level `groups`); Plan 36-01d completes the alignment.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `serde_yaml_ng` 0.10.0 is still available on crates.io | Standard Stack | Plan 36-02 task 1 (cargo search verification) catches this before commit; recovery is to pin to next available 0.10.x or escalate |
| A2 | Upstream commits b5f0a3ab + bbdf7b85 have not been rebased / amended on upstream/main since 2026-05-12 | Sources | Low — git rev-parse confirmed both resolve; D-19 trailer SHA references the commit at the time of cherry-pick, not the latest upstream HEAD |
| A3 | Phase 17 attach-streaming integration test in `crates/nono-cli/tests/attach_streaming_integration.rs` (verified to exist) is the correct test surface to gate D-36-D3 regression coverage | Common Pitfalls | Medium — if other Phase 17 tests exist in module paths I didn't grep, planner should expand the test-gate list |
| A4 | The 11-field ExecConfig enumeration in D-36-D1 maps cleanly to the 17 actual fields in fork's exec_strategy.rs:276 ExecConfig struct, with the gap due to fields being on sibling structs (`ExecutionFlags`, `SupervisedRuntimeContext`, `LaunchPlan`) | Code Examples Pattern 4 | Low — Plan 36-03 Commit 2 task explicitly enumerates the 17 ExecConfig fields and confirms preservation; the D-36-D1 invariant is "preserve shape" not "exactly these field names" |
| A5 | `policy.json`'s top-level `groups` shape is the canonical target alignment from upstream `f0abd413` | System Architecture Diagram | Low — verified via Read; partial alignment confirmed. Plan 36-01d task 1 (audit alignment) addresses any residual gap |
| A6 | Phase 35 closure (Plan 35-03) successfully replaced all `format!("{:?}")` JSON-emission sites in `profile_cmd.rs` | Integration Points | Low — confirmed via git log of Plan 35-03 closing commits 66d7a386 + d8cb250b on 2026-05-12; Plan 36-01b/c/d compose on top of this corrected JSON shape |
| A7 | `scripts/regenerate-schema.sh` exists and is shell-compatible on the Windows dev host (mentioned in CONTEXT.md line 181 but not verified in my read pass) | Per-Plan Approach Plan 36-01d | Medium — Plan 36-01d task 4 (verify reproducibility) catches this; recovery is to add a `.ps1` variant or skip the regeneration if a `.sh` version exists and is callable via Git Bash |

## Open Questions

1. **`policy_cmd.rs` references in CONTEXT.md + deferred-items.md + profile/mod.rs:430**
   - What we know: The file does NOT exist in fork. Three other documents reference it as if it does.
   - What's unclear: Whether to (a) add a stub `policy_cmd.rs` for upstream parity, (b) update the references to point at the actual fork files (`profile_cmd.rs` + `policy.rs`), or (c) ignore as documentation drift.
   - Recommendation: Option (b) — Plan 36-01c PLAN.md replaces the upstream file list with the verified 17-file fork shape; the stale references in CONTEXT.md / deferred-items.md / profile/mod.rs:430 stay as historical record (not corrected mid-plan). At Phase 36 close, `/gsd-progress` or a post-phase cleanup pass updates the stale references.

2. **Exact upstream LOC count for `deprecated_schema.rs`**
   - What we know: CONTEXT.md cites "824 LOC" port. deferred-items.md cites the same.
   - What's unclear: I did not run `git show upstream/f0abd413:crates/nono-cli/src/deprecated_schema.rs | wc -l` to confirm. The 824-LOC figure is a planning estimate.
   - Recommendation: Plan 36-01a executor confirms LOC via `git show f0abd413:crates/nono-cli/src/deprecated_schema.rs | wc -l` at task 1 start; if dramatically different, escalate via D-34-D2 close-gate STOP trigger.

3. **`scripts/regenerate-schema.sh` Windows compatibility**
   - What we know: CONTEXT.md mentions the script but I did not verify it exists or runs on Windows.
   - What's unclear: Whether Plan 36-01d's "verify reproducibility" task requires adding a `.ps1` variant for Windows dev host.
   - Recommendation: Plan 36-01d task 1 includes a Windows-host compatibility check; if missing, add `.ps1` variant as a sub-task (mirroring `scripts/test-linux.sh` ↔ `scripts/windows-test-harness.ps1` precedent).

4. **PTY-quiet-period compromise threshold (250 → 100ms vs 150ms)**
   - What we know: CONTEXT.md D-36-D3 mandates explicit regression coverage; v2.5-FU-6 deferral covers parametric formalization.
   - What's unclear: If 100ms surfaces a Phase 17 / Phase 31 flake, is 150ms the acceptable compromise vs. rolling back the change entirely?
   - Recommendation: Plan 36-03 PLAN.md acceptance criteria include: "if 100ms surfaces a flake, EITHER compromise to 150ms (locked at plan close) OR rollback the quiet-period rider entirely and defer to v2.5-FU-6." The planner does NOT pre-decide; the executor escalates if the flake surfaces.

5. **Whether `profile/mod.rs:1638` `#[serde(alias = "brokered_commands")]` is in scope for Plan 36-01c rename**
   - What we know: It's a separate alias for `command_args`, unrelated to `override_deny` rename.
   - What's unclear: Whether the canonical sections in Plan 36-01b touch `command_args` (likely yes — `commands.allow` / `commands.deny`).
   - Recommendation: Plan 36-01b task 4 (`From<ProfileDeserialize>` impl update) addresses `command_args` placement under `commands` section if upstream's f0abd413 puts it there. Verify against upstream's canonical schema.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust toolchain (cargo) | All plans | ✓ | (workspace 1.77+, per Cargo.toml) | — |
| `git` CLI + `git remote upstream` | Plan 36-03 Commit 3 D-19 cherry-pick of bbdf7b85; design-source citations for other commits | ✓ | (verified `git remote -v` returns `upstream https://github.com/always-further/nono.git`) | — |
| `gh` CLI | PR creation | ✓ | (per memory/feedback_gh_available.md) | — |
| `cargo clippy --target x86_64-unknown-linux-gnu` | Close-gate step 3 (Linux cross-target clippy) | ✓ ASSUMED | — | If toolchain missing, executor installs via `rustup target add x86_64-unknown-linux-gnu` |
| `cargo clippy --target x86_64-apple-darwin` | Close-gate step 4 (macOS cross-target clippy) | ✓ ASSUMED | — | If toolchain missing, executor installs via `rustup target add x86_64-apple-darwin` |
| `cargo fmt --all -- --check` | Close-gate step 5 | ✓ | — | — |
| `serde_yaml_ng` 0.10.0 on crates.io | Plan 36-02 | ✓ ASSUMED | — | Pin to next 0.10.x if 0.10.0 unavailable; escalate if multiple 0.10.x versions broken |
| `jsonschema` 0.46 (dev-dep) | Plan 36-01d schema fixture tests | ✓ | (verified Cargo.toml:109) | — |
| Phase 17 attach-streaming test surface (`crates/nono-cli/tests/attach_streaming_integration.rs`) | Plan 36-03 D-36-D3 regression coverage | ✓ | (verified via Glob) | — |
| Phase 31 broker (`crates/nono-shell-broker/src/main.rs`) | Plan 36-03 D-36-D3 broker ConPTY regression | ✓ | (verified via Glob) | — |
| `scripts/regenerate-schema.sh` | Plan 36-01d schema-regenerate verification | ? UNKNOWN | — | Add `.ps1` variant if missing on Windows host |
| `scripts/test-list-aliases.sh` | Plan 36-01d alias inventory enforcement | ✗ (new file) | — | NEW — Plan 36-01d creates |
| `scripts/lint-docs.sh` | Plan 36-01d docs alias-inventory check | ✗ (new file) | — | NEW — Plan 36-01d creates |

**Missing dependencies with no fallback:**
- None.

**Missing dependencies with fallback:**
- `scripts/test-list-aliases.sh` and `scripts/lint-docs.sh` — NEW files, Plan 36-01d creates them; not blocking, they ARE the deliverable.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust's built-in test runner (`cargo test`) + `proptest` 1 (workspace dev-dep) + `jsonschema` 0.46 (dev-dep) for schema validation |
| Config file | None (uses workspace `Cargo.toml`; tests live alongside source as `#[cfg(test)]` modules + `crates/<crate>/tests/` integration tests) |
| Quick run command | `cargo test --workspace --all-features` |
| Full suite command | `cargo test --workspace --all-features` (same — no separate slow suite per CLAUDE.md) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|--------------|
| REQ-PORT-CLOSURE-02 (acc #1: LegacyPolicyPatch struct present + serde alias) | Plan 36-01a — legacy `override_deny` keys deserialize and rewrite to canonical `bypass_protection` post-parse | unit | `cargo test --workspace --all-features deprecated_schema::tests::legacy_policy_patch_rewrites` | ❌ Wave 0 (Plan 36-01a creates) |
| REQ-PORT-CLOSURE-02 (acc #2: per-key DeprecationCounter) | Plan 36-01a — first-encounter-per-process emission semantics; tracked separately per legacy key | unit | `cargo test --workspace --all-features deprecated_schema::tests::deprecation_counter_emits_once` | ❌ Wave 0 (Plan 36-01a creates) |
| REQ-PORT-CLOSURE-02 (acc #3: --strict mode fails closed) | Plan 36-01a — `nono profile validate --strict` returns non-zero exit + clear error pointing to canonical key | integration | `cargo test --workspace --all-features --test profile_cli test_profile_validate_strict_rejects_legacy_keys` | ❌ Wave 0 (Plan 36-01a creates) |
| REQ-PORT-CLOSURE-02 (acc #4: schema regenerate matches upstream canonical form) | Plan 36-01d — `scripts/regenerate-schema.sh` produces matching output | smoke (script) | `bash scripts/regenerate-schema.sh && git diff --exit-code crates/nono-cli/data/nono-profile.schema.json` | ✓ (regenerate-schema.sh exists per CONTEXT.md; verify Windows-callable) |
| REQ-PORT-CLOSURE-02 (acc #5: built-in profiles migrated to canonical sections) | Plan 36-01d — claude-code, codex, opencode, claude-no-keychain all use canonical sections | unit | `cargo test --workspace --all-features profile::builtin::tests::all_profiles_use_canonical_sections` | ❌ Wave 0 (Plan 36-01d creates) |
| REQ-PORT-CLOSURE-02 (acc #6: docs alias-inventory check) | Plan 36-01d — `scripts/lint-docs.sh` passes | smoke (script) | `bash scripts/lint-docs.sh` | ❌ Wave 0 (Plan 36-01d creates) |
| REQ-PORT-CLOSURE-04 (acc #2: yaml_merge directive accepted) | Plan 36-02 — `nono profile patch --yaml <overlay>` accepts `yaml_merge:` directives matching upstream semantics | integration | `cargo test --workspace --all-features --test profile_cli test_profile_patch_yaml_merge_directive` | ❌ Wave 0 (Plan 36-02 creates) |
| REQ-PORT-CLOSURE-04 (acc #3: serde_yaml_ng pinned 0.10.0) | Plan 36-02 — `Cargo.toml` dep line `serde_yaml_ng = "=0.10.0"` | smoke (build) | `cargo tree --workspace --depth 1 \| grep 'serde_yaml_ng v0.10.0'` | ✓ (Cargo.toml will exist post-edit) |
| REQ-PORT-CLOSURE-04 (acc #4: reversal failure test) | Plan 36-02 — upstream `242d4917` reversal failure test passes | unit | `cargo test --workspace --all-features wiring::tests::test_yaml_merge_reversal_failure` | ❌ Wave 0 (Plan 36-02 creates) |
| REQ-PORT-CLOSURE-04 (acc #1: idempotent JSON-merge install records) | **EXPLICITLY scope-trimmed to v2.5-FU-3 per D-36-C1**; not satisfied in Phase 36 | n/a | n/a — out of scope | n/a |
| REQ-PORT-CLOSURE-05 (acc #1: ExecConfig accepts upstream shape OR fork preserves) | Plan 36-03 — fork preserves 17-field ExecConfig per D-36-D1 | smoke (compile) | `cargo build --workspace --all-features` | ✓ (existing structure preserved) |
| REQ-PORT-CLOSURE-05 (acc #2: macOS learn diagnostic improvements) | Plan 36-03 Commit 2 — `nono learn` on macOS prints improved guidance per b5f0a3ab | unit | `cargo test --workspace --all-features --target x86_64-apple-darwin learn_runtime::tests::print_macos_run_guidance` | ✓ (Plan 34-08b absorbed; verify still present) |
| REQ-PORT-CLOSURE-05 (acc #3: PTY-quiet-period absorbed without regression) | Plan 36-03 Commit 2 — `POST_EXIT_PTY_DRAIN_TIMEOUT` 250→100ms; Phase 17 attach-streaming + Phase 31 broker ConPTY both pass | integration | `cargo test --workspace --all-features --test attach_streaming_integration` AND Phase 15 5-row smoke gate (manual via `nono run --detached` → `nono ps` → `nono attach` → detach → `nono stop`) | ✓ (`attach_streaming_integration.rs` exists; Phase 15 smoke is manual) |
| REQ-PORT-CLOSURE-05 (acc #4: bbdf7b85 escape-quote test passes) | Plan 36-03 Commit 3 — `test_analyze_error_output_detects_structured_path_with_escaped_quote` from bbdf7b85 passes | unit | `cargo test --workspace --all-features diagnostic::tests::test_analyze_error_output_detects_structured_path_with_escaped_quote` | ❌ Wave 0 (Plan 36-03 Commit 3 creates) |

### Sampling Rate
- **Per task commit:** `cargo build --workspace --all-features && cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (fast — clippy catches the bulk of regressions before tests).
- **Per wave merge:** Full close-gate sequence (D-36-A5 steps 1-8): `cargo test --workspace --all-features` + Windows clippy + Linux cross-target clippy + macOS cross-target clippy + `cargo fmt --check` + Phase 15 5-row detached-console smoke + `wfp_port_integration` (or skip-documented) + `learn_windows_integration` (or skip-documented).
- **Phase gate:** All 8 close-gate steps pass on Windows host; CI Linux + macOS lanes green (deferred verification for cfg-gated code paths the Windows host cannot exercise).

### Wave 0 Gaps
Tests NOT yet existing that Phase 36 plans must create:
- [ ] `crates/nono-cli/src/deprecated_schema.rs` `#[cfg(test)]` module — covers REQ-PORT-CLOSURE-02 #1 + #2 (Plan 36-01a).
- [ ] `crates/nono-cli/tests/profile_cli.rs::test_profile_validate_strict_rejects_legacy_keys` — covers REQ-PORT-CLOSURE-02 #3 (Plan 36-01a).
- [ ] `crates/nono-cli/src/profile/builtin.rs::tests::all_profiles_use_canonical_sections` — covers REQ-PORT-CLOSURE-02 #5 (Plan 36-01d).
- [ ] `scripts/lint-docs.sh` itself + integration check — covers REQ-PORT-CLOSURE-02 #6 (Plan 36-01d).
- [ ] `crates/nono-cli/src/wiring.rs` `#[cfg(test)]` module with reversal failure test — covers REQ-PORT-CLOSURE-04 #4 (Plan 36-02).
- [ ] `crates/nono-cli/tests/profile_cli.rs::test_profile_patch_yaml_merge_directive` — covers REQ-PORT-CLOSURE-04 #2 (Plan 36-02).
- [ ] Plan 36-02 path-validation tests for yaml_merge target (`../../../`, UNC, symlink) — covers Common Pitfall 6.
- [ ] `crates/nono/src/diagnostic.rs::tests::test_analyze_error_output_detects_node_eperm_mkdir_as_write` — covers REQ-PORT-CLOSURE-05 #4 setup (Plan 36-03 Commit 1).
- [ ] `crates/nono/src/diagnostic.rs::tests::test_analyze_error_output_detects_structured_node_eperm_mkdir_path` — covers REQ-PORT-CLOSURE-05 #4 (Plan 36-03 Commit 3).
- [ ] `crates/nono/src/diagnostic.rs::tests::test_analyze_error_output_detects_structured_path_with_escaped_quote` — covers REQ-PORT-CLOSURE-05 #4 (Plan 36-03 Commit 3; bbdf7b85's native test).
- [ ] `crates/nono-cli/src/execution_runtime.rs::tests::*` — covers startup-timeout interactive vs non-interactive arms (Plan 36-03 Commit 2).

**Framework install:** None — `cargo test` is built into the Rust toolchain (already in environment). No additional dependencies.

## Security Domain

`security_enforcement` is enabled (absent from `.planning/config.json` is treated as enabled).

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|------------------|
| V2 Authentication | no | Phase 36 does not introduce auth surfaces; the sandbox model is identity-free for the child process |
| V3 Session Management | no | Phase 36 does not introduce session surfaces; existing supervisor IPC session model is unaffected |
| V4 Access Control | yes | Sandbox capability model (allow/deny) is the entire Phase 36 deprecated_schema port surface. Canonical `commands.{allow,deny}` + `filesystem.{deny,bypass_protection}` sections are access-control primitives. `nono profile validate --strict` is an access-control fail-closed lever |
| V5 Input Validation | yes | `LegacyPolicyPatch` deserialization of JSON profile files (Plan 36-01a) MUST reject malformed input cleanly via serde + thiserror. yaml_merge directive parser (Plan 36-02) MUST reject malformed YAML cleanly. Path validation for yaml_merge targets MUST use `Path::components()` iteration (Plan 36-02) |
| V6 Cryptography | no | Phase 36 does NOT introduce crypto surfaces. Existing sigstore-verify + sigstore-sign + zeroize primitives untouched |
| V11 Business Logic | yes | LegacyPolicyPatch rewriter MUST preserve semantic equivalence between legacy and canonical keys (round-trip invariant). `--strict` mode MUST be fail-closed (default-deny on legacy keys). DeprecationCounter MUST emit per-key first-encounter-only per-process (no duplicate warnings; no missed warnings) |
| V12 File and Resources | yes | yaml_merge target-path validation (Plan 36-02). Profile JSON file load (Plan 36-01a). Existing `validate_path_within` defense-in-depth retention catalog entry MUST be preserved. JSON profile file size limits should be considered (currently no explicit size cap on profile load — verify upstream f0abd413 carries one; if so, port; if not, defer to v2.5+) |
| V14 Configuration | yes | `serde_yaml_ng` 0.10.0 pin (Plan 36-02) is a security-relevant dependency version lock. `serde_yaml` (deprecated/unmaintained) MUST NOT be added |

### Known Threat Patterns for nono fork stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Malformed profile JSON crashes the loader | Denial of Service | Plan 36-01a `LegacyPolicyPatch` uses serde + thiserror for clean error returns; no `.unwrap()`/`.expect()` |
| Legacy `override_deny` key on a JSON profile silently NOT applied | Tampering / Elevation of Privilege | Plan 36-01a `LegacyPolicyPatch` rewriter ensures legacy keys are normalized to canonical form post-parse; both keys deserialize correctly. Test: round-trip invariant test (legacy JSON → load → re-serialize → compare to canonical form) |
| Strict mode silently accepts legacy keys (regression) | Elevation of Privilege | Plan 36-01a `--strict` mode fails closed with non-zero exit. Test: `test_profile_validate_strict_rejects_legacy_keys` integration test |
| yaml_merge target-path escape via `../../../etc/passwd` | Tampering / Elevation of Privilege | Plan 36-02 target-path validation uses `Path::components()` iteration + canonicalization; `validate_path_within` defense-in-depth callsites preserved (CLAUDE.md § Common Footguns #1) |
| yaml_merge directive accepting upstream-shape but rejecting fork-extensions | Information Disclosure | Plan 36-02 verifies fork's profile-patch idioms compose with upstream's yaml_merge directive; if fork's `add_allow_readwrite` / `add_deny_commands` shape diverges, plan body documents adaptation |
| PTY-quiet-period 100ms drains output too early, leaking partial child-process state | Information Disclosure | Plan 36-03 Commit 2 D-36-D3 explicit regression coverage on Phase 17 attach-streaming + Phase 31 broker ConPTY |
| ExecConfig field deletion regresses fork's audit-attestation (capability_elevation, audit_signer, etc.) | Repudiation / Elevation of Privilege | Plan 36-03 D-36-D1 invariant: do NOT modify ExecConfig struct. Surgical port targets function bodies + helpers + new const + LearnArgs.trace only |
| Escape-quote bypass in `extract_structured_string_property` allows attacker to spoof diagnostic output | Information Disclosure / Tampering | Plan 36-03 Commit 3 bbdf7b85 body rewrite handles escape-quoted characters correctly; 2 new tests lock the invariant |
| LegacyPolicyPatch silently accepting unknown keys (no `#[serde(deny_unknown_fields)]`) | Tampering | Plan 36-01a should preserve `deny_unknown_fields` semantics. Verify `PolicyPatchConfig` struct at profile/mod.rs:441 (or its successor in deprecated_schema.rs) retains `#[serde(deny_unknown_fields)]` |
| `--strict` mode regression in CI but not on dev host | Tampering | Close-gate step 1 (`cargo test --workspace --all-features`) catches; integration test deterministic across platforms |

**Cross-cutting:** All Phase 36 plans inherit CLAUDE.md § Security Considerations: principle of least privilege; defense in depth; fail secure; explicit over implicit. D-34-B2 surgical-retrofit posture explicitly forbids broadening security surface beyond what upstream's port carries.

## Sources

### Primary (HIGH confidence)
- [VERIFIED via Read] `.planning/phases/36-upst3-deep-closure/36-CONTEXT.md` — 286 lines; locked decisions D-36-A1..A6/B1..B4/C1..C2/D1..D3/E1..E2; canonical references section; specifics; deferred ideas.
- [VERIFIED via Read] `.planning/REQUIREMENTS.md` — REQ-PORT-CLOSURE-02 (lines 42-54), REQ-PORT-CLOSURE-04 (lines 69-79), REQ-PORT-CLOSURE-05 (lines 81-91); Traceability table line 201-204.
- [VERIFIED via Read] `.planning/ROADMAP.md` lines 145-167 — Phase 36 + Phase 36.5 sections.
- [VERIFIED via Read] `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md` — P34-DEFER-04b-1 (lines 6-49), P34-DEFER-06-1 (lines 127-159), P34-DEFER-08b-1 (lines 203-265), P34-DEFER-08b-2 (lines 267-316), P34-DEFER-09-2 (lines 351-388). Phase 35 closure section lines 490-580.
- [VERIFIED via Read] `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md` — D-34-A1..E5 decisions; binding precedents D-36-A1..A6/B2/D2 inherit from.
- [VERIFIED via Read] `.planning/phases/35-upst3-closure-quick-wins/35-CONTEXT.md` — D-35-A1..D4 sister-phase precedents.
- [VERIFIED via Read] `.planning/templates/upstream-sync-quick.md` — D-19 trailer block lines 219-235; Conflict-file inventory; Fork-divergence catalog.
- [VERIFIED via Read] `crates/nono/src/diagnostic.rs` lines 395-419 + 2250-2280 — deferred-state comment blocks confirmed at line 402-419 + 2258-2267.
- [VERIFIED via Read] `crates/nono-cli/src/exec_strategy.rs` lines 270-330 — ExecConfig struct at line 276 with 17 pub fields; clear_signal_forwarding_target at line 1987.
- [VERIFIED via Read] `crates/nono-cli/src/profile/mod.rs` lines 1-70 + 200-225 + 410-440 + 1620-1675 — Phase 34-04b Option C scaffolding at lines 47/439/1359/1364 confirmed; FilesystemConfig at line 205; LEGACY_OVERRIDE_DENY_WARNED AtomicBool at line 47.
- [VERIFIED via Read] `crates/nono-cli/Cargo.toml` 111 lines — no serde_yaml_ng dep currently; will add per Plan 36-02.
- [VERIFIED via Read] `crates/nono-cli/data/policy.json` lines 1-80 — top-level `groups` shape already aligns with upstream canonical structure.
- [VERIFIED via git rev-parse] All 8 upstream commits resolve from `upstream` remote: b5f0a3ab (Luke Hinds, 2026-05-09), bbdf7b85 (Luke Hinds, 2026-05-10), 242d4917 (Luke Hinds, 2026-05-07), 802c8566 (Advaith Sujith, 2026-05-06), d44f5541 (Advaith Sujith, 2026-05-06), f0abd413 (Leo Lapworth, 2026-05-01), 24d8b924 (Luke Hinds, 2026-04-25), bdf183e9 (Luke Hinds, 2026-04-28).
- [VERIFIED via git remote -v] `upstream` remote points to `https://github.com/always-further/nono.git` as documented in CONTEXT.md line 199.
- [VERIFIED via git log] No drift since CONTEXT.md was gathered 2026-05-12; only context-recording commits (`c46be15b`, `ea2d0740`) between then and now.
- [VERIFIED via Grep] 183 callsites of `override_deny` across 17 files in `crates/nono-cli/src/` (NOT 210/14 as CONTEXT.md claims).
- [VERIFIED via ls] `crates/nono-cli/src/policy_cmd.rs` does NOT exist (drift finding 1).
- [VERIFIED via ls] `crates/nono-cli/src/wiring.rs` does NOT exist (Plan 36-02 will create).
- [VERIFIED via ls] `crates/nono-cli/src/deprecated_schema.rs` does NOT exist (Plan 36-01a will create).
- [VERIFIED via Read] `CLAUDE.md` § Coding Standards, § Path Handling, § Security Considerations.

### Secondary (MEDIUM confidence)
- [CITED: deferred-items.md § P34-DEFER-04b-1] Upstream deprecated_schema module is "824 LOC" — planning estimate; confirm exact LOC at Plan 36-01a task 1.
- [CITED: CONTEXT.md line 199] Upstream remote URL = `https://github.com/always-further/nono.git` — verified independently via `git remote -v`.

### Tertiary (LOW confidence)
- [ASSUMED] `serde_yaml_ng` 0.10.0 still available on crates.io — recommend executor `cargo search serde_yaml_ng` before commit.
- [ASSUMED] `scripts/regenerate-schema.sh` exists and runs on Windows host — Plan 36-01d task 1 verifies.
- [ASSUMED] The `b5f0a3ab` macOS-gated code paths (`print_macos_run_guidance` per Plan 34-08b absorption) are still present in `crates/nono-cli/src/learn_runtime.rs` — verify before Plan 36-03 Commit 2 starts to avoid double-absorbing.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — All deps verified in Cargo.toml; new dep (serde_yaml_ng) is upstream's locked choice from a known commit.
- Architecture: HIGH — Locked decisions in CONTEXT.md cover plan slicing, sequencing, commit shapes, close gate, and carry-forward invariants. Three drift findings are file-naming/count corrections, not scope changes.
- Pitfalls: HIGH — All 7 pitfalls grounded in verified source-file state (deferred-state comment blocks, existing helper locations, typo at cli.rs:2272, etc.).
- Validation: HIGH — Test surfaces verified to exist (attach_streaming_integration.rs, nono-shell-broker); new tests enumerated per requirement acceptance criteria.
- Security: HIGH — ASVS V4/V5/V11/V12/V14 categories grounded in CLAUDE.md + locked decisions; threat patterns mapped to STRIDE.

**Research date:** 2026-05-12.
**Valid until:** 2026-06-11 (30 days; stable phase scope locked at discuss; upstream commits already merged so no upstream churn risk).

## RESEARCH COMPLETE
