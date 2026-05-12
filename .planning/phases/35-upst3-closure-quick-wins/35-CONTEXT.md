# Phase 35: UPST3-closure quick wins - Context

**Gathered:** 2026-05-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Close three discrete Phase 34 NEEDS-FOLLOW-UP-PLAN deferrals targeting Windows/Linux parity gaps and Windows test-harness hygiene. Phase 35 is regression closure (not an upstream-sync phase): each REQ back-ports a specific upstream pattern or fixes a fork-local regression introduced during the Phase 34 cherry-pick chain. Total estimate ~2 weeks across 3 wave-parallel plans.

**In scope:**
- **REQ-PORT-CLOSURE-01** (P34-DEFER-08a-1, ~3-5 days) — Wire `allowed_env_vars` / `denied_env_vars` consumption into `crates/nono-cli/src/exec_strategy_windows/` so Windows enforces the env filter that Plan 34-08a added to the cross-platform path. Mirrors upstream `1b412a7` v0.37.0 env-filter surface + the empty-allow fail-closed invariant from `780965d7`.
- **REQ-PORT-CLOSURE-06** (P34-DEFER-09-1, ~2-3 days) — Cherry-pick upstream `bdf183e9` 15-line Linux Landlock hunk in `crates/nono-cli/src/profile_runtime.rs`: pre-create `~/.config/nono/profiles/` before Landlock ruleset apply. Eliminates the confusing "no such file or directory" error on first invocation.
- **REQ-PORT-CLOSURE-07** (P34-DEFER-01-1 + P34-DEFER-10-1, ~3-5 days) — Fix `query_ext::test_query_path_denied` Windows UNC long-path flake at the production-code source (strip `\\?\` prefix in `suggested_flag` emission, mirroring commit `400f8c90`) + restore the `f3e7f885` Map-based emission of `Option<…>` security fields in `profile_cmd.rs::profile_to_json` / `::diff_to_json` so the Rust-Debug-format leak (`"Some(Isolated)"`) goes away. Closes the entire `format!("{:?}")` JSON-leak regression class via full audit.

**Out of scope (route elsewhere or explicitly defer):**
- **REQ-PORT-CLOSURE-05 (P34-DEFER-08b-1 + P34-DEFER-08b-2)** — `b5f0a3ab` deep ExecConfig refactor + `bbdf7b85` escape-quote pipeline rider. Moved to Phase 36 per ROADMAP § Phase 35 scope note (the v2.4 PROJECT.md summary line that still mentions "08b-2" is stale; ROADMAP + REQUIREMENTS.md are authoritative). The escape-quote pipeline depends on the 08b-1 ExecConfig refactor; both belong together in Phase 36's deep-closure plan.
- **REQ-PORT-CLOSURE-02 / 03 / 04** — Phase 36 (deep closure: deprecated_schema module, profile drafts, yaml_merge wiring trio + wiring.rs base).
- **All v2.3 host-blocked carry-forwards** — REQ-RESL-NIX-01..03 + REQ-PKGS-01 + REQ-PKGS-04 are Phase 37 (Linux/macOS host execution of Plan 25-01 + Plan 26-02).
- **Audit-event retrofit for Windows env-filter outcomes** — Plan 34-08a's Unix wiring doesn't emit env-filter audit events either; adding one for Windows would diverge from upstream and create load-bearing fork surface (D-34-B2 surgical-retrofit posture inheritance).
- **Integration tests via `run_nono`** — STATE.md-documented `dirs::home_dir()` Windows blocker. Unit tests cover the env-filter invariants on Windows; integration tests defer to Phase 37/38 when Linux/macOS host is available.
- **Refactoring SignalMode JSON emission elsewhere** beyond `profile_cmd.rs` — the audit (D-35-C3) is scoped to `format!("{:?}")` sites in JSON-emission helpers in `profile_cmd.rs`; other files retain their current shape.

</domain>

<decisions>
## Implementation Decisions

### Plan slicing & invariants (Area A)

- **D-35-A1: D-34-E1 Windows-only-files invariant explicitly inverted for Phase 35, scoped to REQ-PORT-CLOSURE-01 surface only.** Plan 35-01 MUST touch `crates/nono-cli/src/exec_strategy_windows/` (that's the whole REQ). Other Windows-gated files (`learn_windows.rs`, `pty_proxy_windows.rs`, `session_commands_windows.rs`, etc.) stay byte-identical. REQ-07 also touches Windows-host test paths but only via production-code changes in `query_ext.rs` (cross-platform) and `profile_cmd.rs` (cross-platform JSON emission) — no `*_windows.rs` edits required for REQ-07. Plan 35-02 (Linux Landlock) and Plan 35-03 (test hygiene) both honor D-34-E1 unchanged. The `gsd-plan-checker` and any future audit walking Phase 34's invariants must read D-35-A1 before flagging Plan 35-01.

- **D-35-A2: Three plans, one per REQ — 35-01-WIN-ENV-FILTER (REQ-PORT-CLOSURE-01), 35-02-LINUX-LANDLOCK-PROFILES (REQ-PORT-CLOSURE-06), 35-03-WIN-TEST-HYGIENE (REQ-PORT-CLOSURE-07).** Mirrors Phase 34 D-34-A1 one-plan-per-cluster discipline. Each plan owns its REQ's acceptance criteria end-to-end (planning, execution, plan-close gate, PR review surface).

- **D-35-A3: Wave-parallel — all 3 plans in one wave.** Surfaces are fully disjoint: `exec_strategy_windows/` (REQ-01) vs `profile_runtime.rs` Linux hunk (REQ-06) vs `query_ext.rs` + `profile_cmd.rs` (REQ-07). No file overlap; no ordering dependency. Phase 22 D-09 / D-10 / D-12 "wave-parallel by disjoint surface" precedent applies. Planner may serialize execution if dev-host scheduling makes parallel easier to land sequentially — wave shape is a parallelism-allowed-not-mandated lock.

- **D-35-A4: D-19 trailer convention scoped to commits with a direct upstream commit credit.**
  - **Plan 35-02 (REQ-06)** — full 6-line D-19 trailer block on the cherry-pick commit (`Upstream-commit: bdf183e9` etc.). The Landlock hunk is a clean stand-alone cherry-pick from upstream v0.44.0; the surrounding upstream `bdf183e9` work (188/239 lines in upstream's `wiring.rs`) is NOT picked up — only the 15-line `profile_runtime.rs` hunk.
  - **Plan 35-01 (REQ-01)** — D-20 manual-replay shape; commit body references upstream `1b412a7` (v0.37.0 env-filter surface) + Plan 34-08a (Unix wiring landed in fork) but no cherry-pick (the Windows wiring is Windows-specific code with no upstream analog).
  - **Plan 35-03 (REQ-07)** — fork-local regression fixes; no D-19 trailer. Regular DCO sign-off only. Commit body references upstream `f3e7f885` (v0.47.0 JSON shape pattern) and commit `400f8c90` (production-code UNC strip analog) as design-source citations, not back-ports.

### REQ-01 — Windows env-filter wiring (Area B)

- **D-35-B1: Tests live in `exec_strategy_windows/` only — no `run_nono` integration tests in Phase 35.** Function-call-boundary unit tests in `crates/nono-cli/src/exec_strategy_windows/` (or its submodule that constructs the child process environment block). Integration via `run_nono` would hit the STATE.md-documented `dirs::home_dir()` Windows blocker, which is a Phase 37-class issue. Phase 35 stays Windows-host-friendly.

- **D-35-B2: Mirror the Unix `exec_strategy.rs` env-filter call site shape.** Find where Unix calls the `should_skip_env_var`-style filter (added by Plan 34-08a). Add the symmetric call inside `crates/nono-cli/src/exec_strategy_windows/mod.rs` (or whichever submodule builds the child PEB env block). Remove the `#[cfg_attr(target_os = "windows", allow(dead_code))]` gates on `allowed_env_vars` / `denied_env_vars` in the Windows `ExecConfig` shape. Cleanest parity expression; lowest risk of Unix/Windows drift if upstream evolves the filter shape in v0.53+.

- **D-35-B3: Validation = Windows-gated unit test + cross-platform invariant check.** Add `#[cfg(target_os = "windows")]` test `test_windows_empty_allow_denies_all_env_vars` asserting the spawned child's env block contains zero user env vars on `allow_vars: []` + no `deny_vars` (the `780965d7` fail-closed invariant). Plus a cross-platform unit test on the filter helper itself (whatever shape that takes per D-35-B2) so the empty-allow invariant is locked at the abstraction layer regardless of platform.

- **D-35-B4: No audit-event retrofit for the env-filter outcome.** Plan 34-08a's Unix wiring doesn't emit audit events for env-filter outcomes either. Adding Windows-side audit emission would create cross-platform asymmetry and become load-bearing fork surface (D-34-B2 surgical-retrofit posture). If audit visibility for env filtering becomes a requirement later, it gets its own phase + cross-platform decision.

### REQ-07 — Test hygiene + JSON shape (Area C)

- **D-35-C1: Fix UNC flake at the production-code source.** Strip the `\\?\` prefix in the `suggested_flag` value emitted by `query_path` in `crates/nono-cli/src/query_ext.rs`. Mirrors the shape of commit `400f8c90` (production-code UNC strip for `query_path` sensitive-path check). Test `test_query_path_denied` then passes deterministically on Windows + Linux + macOS with no `#[cfg]` gates. Closes the latent UX bug where suggested CLI flags contained literally untypeable `\\?\C:\…` syntax. Both P34-DEFER-01-1 and P34-DEFER-09-3 (a carry-forward duplicate of 01-1) close with this single fix.

- **D-35-C2: JSON shape for `Option<…>` security fields — `Some(value)` → snake_case string; `None` → field omitted from JSON object.** Match upstream `f3e7f885` (v0.47.0) shape per Plan 34-04b SUMMARY's "Map-insertion for Option<…> Security fields, omitted-when-None semantics" expectation. For `Option<SignalMode>`: `Some(Isolated)` → `"signal_mode": "isolated"`; `None` → field absent. Replace the offending `format!("{:?}", profile.security.signal_mode)` at `profile_cmd.rs:1056` (`profile_to_json`) and `:1303` (`diff_to_json`) with `serde_json::to_value`-driven Map insertion. Verify the `SignalMode` enum has `#[serde(rename_all = "snake_case")]` (or equivalent) on its `derive(Serialize)` — if not, add it.

- **D-35-C3: Audit the full set of `format!("{:?}")` / `format!("{:#?}")` sites inside `profile_cmd.rs` JSON-emission helpers and fix every Option<…> security field that leaks Rust Debug.** Don't stop at `signal_mode`. Grep `profile_cmd.rs` for `format!("{:?}` and `format!("{:#?}` — any occurrence inside `profile_to_json`, `diff_to_json`, or any sibling JSON emitter must be replaced with proper serde-driven emission. Closes the entire regression class identified by P34-DEFER-10-1 (which speculated about Plan 34-08b or 34-09 having re-introduced the Debug-format fallback after Plan 34-04b's `f3e7f885` adoption). The two regression tests (`test_policy_show_json_no_rust_debug_syntax` + `test_policy_diff_json_no_rust_debug_syntax`) lock the invariant going forward.

- **D-35-C4: P34-DEFER-09-3 closes transitively via Plan 35-03 — no separate task.** Phase 34 `deferred-items.md` explicitly records 09-3 as a carry-forward duplicate of 01-1 (same test, same failure shape). The D-35-C1 production-code fix closes both. Plan 35-03 SUMMARY notes the transitive closure in its closure-section append to Phase 34's `deferred-items.md` (per D-35-D4).

### PR shape & close gate (Area D)

- **D-35-D1: Three PRs, one per plan — direct-on-main.** Mirrors Phase 34 D-34-D1 ("direct-on-main; one PR per plan"). Reviewer attention concentrates per REQ — Windows env-filter wiring, Linux Landlock pre-create, Windows test-hygiene are three distinct review surfaces. Wave-parallel plan execution (D-35-A3) means all 3 PRs may be open simultaneously; PR-merge ordering follows surface readiness, not REQ number.

- **D-35-D2: Per-plan close gate inherits Phase 34 D-34-D2 verbatim — all 8 steps.** Before each Phase 35 plan can close on the dev host (Windows):
  1. `cargo test --workspace --all-features` (Windows).
  2. `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host).
  3. `cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` — load-bearing for Plan 35-02 (Linux Landlock hunk lives behind `#[cfg(target_os = "linux")]`); also guards against drift in cross-platform code touched by Plans 35-01 + 35-03. Phase 25 CR-A lesson in feedback memory.
  4. `cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` — symmetric coverage for macOS-gated code touched (if any) by the cross-platform JSON-emission refactor in Plan 35-03.
  5. `cargo fmt --all -- --check`.
  6. Phase 15 5-row detached-console smoke gate (`nono run --detached` → `nono ps` → `nono attach` → detach → `nono stop`) — guards against unintended drift in `exec_strategy_windows/` for Plan 35-01.
  7. `wfp_port_integration` test suite (or documented-skipped with admin/service-not-available reason).
  8. `learn_windows_integration` test suite (or documented-skipped).

  **STOP triggers (mid-plan):** any gate (1)–(8) fails. Plan freezes; investigate; either split the plan or roll back to last clean state. Predictable; reviewer sees identical close-gate language as Phase 34.

- **D-35-D3: Plan 35-02 Linux integration verification via CI Linux lane.** The Landlock pre-create hunk is unverifiable on the Windows dev host (Landlock requires Linux kernel 5.13+). Dev-host gate (D-35-D2) provides cross-target Linux clippy coverage. The functional verification (`profile_runtime.rs` pre-creates `~/.config/nono/profiles/` before ruleset apply; no "no such file or directory" error) lands in a Linux-gated integration test marked `#[ignore]` on Windows host but exercised in CI's Linux lane. Plan 35-02 close on Windows requires CI Linux lane green for the new test. Mirrors Phase 25 deferred-to-host pattern for the lighter half (a 15-line hunk + 1 integration test, not a full Plan 25-01-shape RESL backend).

- **D-35-D4: Plan 35-03 (last to close) appends a "Phase 35 closure" section to Phase 34's `deferred-items.md` flipping P34-DEFER-01-1, 08a-1, 09-1, 09-3, 10-1 from open to closed-by-Phase-35.** Each plan SUMMARY records its own closure of the matching P34-DEFER-* entries (Plan 35-01 closes 08a-1; Plan 35-02 closes 09-1; Plan 35-03 closes 01-1 + 09-3 + 10-1). Plan 35-03 — the last to close in any reasonable execution order — owns the consolidated append to `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md`. Future audits read the ledger cleanly.

### Carry-forward from Phase 34 (still binding)

- **D-34-D2 close-gate** (inherited verbatim per D-35-D2).
- **D-34-B2 surgical retrofit posture** — every "while we're here, let's also wire it up" temptation creates load-bearing fork surface. Phase 35 stays narrow: REQ-01 wires the env-filter, full stop; no Windows-specific audit emission, no WFP composition, no MSI integration.
- **D-34-E2 `Upstream-commit:` trailer block** — verbatim 6-line shape from `.planning/templates/upstream-sync-quick.md` applies to Plan 35-02's bdf183e9 cherry-pick (the only commit in Phase 35 with a direct upstream-cherry-pick lineage). Lowercase 'a' in `Upstream-author:`. Smoke check at plan close: `git log --format='%B' main~1..main | grep -c '^Upstream-commit: '` equals 1 for Plan 35-02.
- **D-34-E3 manual-port shape** — Plan 35-01's commit body documents what was ported from Plan 34-08a's Unix wiring + upstream `1b412a7` and why a straight cherry-pick was infeasible (Windows ExecConfig + PEB env-block construction has no upstream analog). D-20 shape.
- **CLAUDE.md § Coding Standards** — no `.unwrap()`, DCO sign-off, `#[must_use]` on critical Results, env-var save/restore in tests. All Phase 35 plans inherit these.

### Claude's Discretion

- **Plan numbering inside Phase 35** — D-35-A2 names plans by REQ theme + REQ number. Planner can pick the exact suffix convention (`35-01-WIN-ENV-FILTER` vs `35-01-PORT-CLOSURE-01` vs `35-01-ENV-FILTER`). Recommended: keep the THEME-readable suffix shape from Phase 34 (e.g., `35-01-WIN-ENV-FILTER`, `35-02-LINUX-LANDLOCK-PROFILES`, `35-03-WIN-TEST-HYGIENE`).
- **Exact wave-parallel execution order** — D-35-A3 permits all 3 plans in parallel; planner may choose to land them sequentially if context-switching cost is high. No correctness implication.
- **Whether `SignalMode` enum needs a `#[serde(rename_all = "snake_case")]` attribute** — verify what's currently on the enum and add if missing; either way, the JSON output must be snake_case per D-35-C2.
- **Exact regression-test naming** in Plan 35-03 — the two existing tests (`test_policy_show_json_no_rust_debug_syntax` + `test_policy_diff_json_no_rust_debug_syntax`) are the locked invariant; any additional regression tests Plan 35-03 wants to add (e.g., a parametric test enumerating all Option<…> security fields) are planner discretion.
- **PR title conventions, draft vs ready-for-review state at open, reviewer assignment** — inherit Phase 34's conventions; not relitigated here.
- **PROJECT.md drift fix timing** — PROJECT.md line 19 still mentions "P34-DEFER-08b-2 (escape-quote structured-property pipeline)" as Phase 35 scope. ROADMAP § Phase 35 + REQUIREMENTS.md `traceability` table both confirm 08b-2 → Phase 36. The drift gets fixed at Phase 35 close via the standard `/gsd-progress` PROJECT.md update path (Phase 35 outcomes overwrite the milestone summary line). Planner doesn't need to address PROJECT.md mid-phase.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase 35 scope sources
- `.planning/ROADMAP.md` § Phase 35 — phase goal + scope note ("Phase 35 ships 01 + 06 + 07 only"; REQ-PORT-CLOSURE-05 moved to Phase 36).
- `.planning/REQUIREMENTS.md` § REQ-PORT-CLOSURE-01 / REQ-PORT-CLOSURE-06 / REQ-PORT-CLOSURE-07 — full What / Enforcement / Security / Acceptance / Maps-to for each REQ.
- `.planning/REQUIREMENTS.md` § Traceability table — confirms REQ-PORT-CLOSURE-05 → Phase 36 (resolves PROJECT.md drift).
- `.planning/PROJECT.md` § Current Milestone — v2.4 milestone shape; note PROJECT.md line 19 has stale 08b-2 reference (resolved by Phase 35 close via `/gsd-progress`).

### Phase 34 deferred-items + decisions (binding precedent)
- `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md` — P34-DEFER-01-1 (Windows UNC test flake), P34-DEFER-08a-1 (Windows env-filter wiring), P34-DEFER-09-1 (Landlock profiles-dir pre-create), P34-DEFER-09-3 (carry-forward duplicate of 01-1), P34-DEFER-10-1 (policy show/diff JSON Rust Debug leak). All five are the Phase 35 closure targets.
- `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md` — D-34-A1 (one-plan-per-cluster), D-34-B2 (surgical retrofit posture), D-34-D1 (direct-on-main; one PR per plan), D-34-D2 (close-gate), D-34-E1 (Windows-only files invariant — explicitly inverted by D-35-A1 for Phase 35), D-34-E2 (D-19 trailer block), D-34-E3 (D-20 manual port).
- `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-PHASE-OUTCOMES.md` — Phase 34 close ledger; informs how Phase 35 records its closures.
- `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08a-ENV-SURFACE-PORT-SUMMARY.md` — Plan 34-08a Unix env-filter wiring shape; the model Plan 35-01 mirrors.
- `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-04-PATH-CANON-SCHEMA-SUMMARY.md` — Plan 34-04b SUMMARY records the "Map-insertion for Option<…> Security fields, omitted-when-None semantics" expectation (D-35-C2 source).

### Sync execution mechanics (REQ-06 only — bdf183e9 cherry-pick)
- `.planning/templates/upstream-sync-quick.md` § D-19 cherry-pick trailer block — verbatim 6-line shape with lowercase 'a' in `Upstream-author:` (used by Plan 35-02 only).
- `docs/cli/development/upstream-drift.mdx` — long-form runbook for the cherry-pick + trailer convention.
- `.planning/PROJECT.md` § Upstream Parity Process — 4-step process (relevant for Plan 35-02).

### Pattern reference (prior phases Phase 35 inherits or analogues)
- `.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-CONTEXT.md` — wave-parallel by disjoint surface precedent (D-09/D-10/D-12); Windows test gating pattern (D-13/D-14).
- `.planning/phases/25-cross-platform-resl-aipc-unix-design/25-CONTEXT.md` + Plan 25-01 — deferred-to-host pattern (informs D-35-D3 Plan 35-02 CI Linux lane verification shape).
- `.planning/phases/26-pkg-streaming-followup/26-01-PKGS-VALIDATORS-PLAN.md` — most recent D-20 manual-replay precedent.

### Source files Phase 35 will touch
- `crates/nono-cli/src/exec_strategy_windows/` (Plan 35-01) — Windows execution path; `mod.rs` + submodules. Find the env-block construction call site (PEB build helper or similar).
- `crates/nono-cli/src/exec_strategy.rs` (Plan 35-01 reference only — do NOT edit) — Unix env-filter call site that Plan 34-08a landed; mirror this shape on Windows.
- `crates/nono-cli/src/profile_runtime.rs` (Plan 35-02) — Linux Landlock ruleset apply site; the 15-line pre-create hunk lands here behind `#[cfg(target_os = "linux")]`.
- `crates/nono-cli/src/query_ext.rs` (Plan 35-03) — `query_path` function + `test_query_path_denied` unit test (line 365). Production-code UNC strip in `suggested_flag` emission.
- `crates/nono-cli/src/profile_cmd.rs` (Plan 35-03) — `profile_to_json` (line 1041) at line 1056 + `diff_to_json` (line 1777) at line 1303. Replace `format!("{:?}", …)` with serde-driven Map insertion. Full audit of `format!("{:?}")` / `format!("{:#?}")` JSON-emission sites in this file.
- `crates/nono-cli/tests/profile_cli.rs` (Plan 35-03) — `test_policy_show_json_no_rust_debug_syntax` + `test_policy_diff_json_no_rust_debug_syntax`; these are the regression tests that must pass deterministically post-fix.

### Coding & security standards
- `CLAUDE.md` § Coding Standards — no `.unwrap()`, DCO sign-off, `#[must_use]` on critical Results.
- `CLAUDE.md` § Testing § Environment variables in tests — save/restore pattern. Relevant for any Plan 35-01 unit tests that touch env-block construction (potentially via `std::env::set_var` to seed test fixtures).
- `CLAUDE.md` § Path Handling — Plan 35-03 UNC strip must use path component comparison, not string `starts_with`; canonicalize before strip.

### Upstream source (git-resolvable from `upstream` remote at `https://github.com/always-further/nono.git`)
- `bdf183e9` (upstream v0.44.0) — `fix(package): harden re-pulls against user edits` — Plan 35-02 cherry-picks the 15-line `profile_runtime.rs` Landlock pre-create hunk only; the remaining 188/239 lines (upstream `wiring.rs`) are deferred to Phase 36 (REQ-PORT-CLOSURE-04 + the wiring.rs base).
- `1b412a7` (upstream v0.37.0) — env-filter surface introduction — design-source citation for Plan 35-01 (no cherry-pick; reference only).
- `780965d7` — empty-allow fail-closed invariant — design-source citation for D-35-B3 test scope.
- `f3e7f885` (upstream v0.47.0) — JSON Map-emission of Option<…> security fields — design-source citation for D-35-C2 (no cherry-pick; reference only). Plan 34-04b adopted this shape; Plan 35-03 restores it where Phase 34 mid-flight commits regressed it.
- `400f8c90` (in-fork commit) — `fix(19-CLEAN-02): strip UNC prefix in query_path sensitive-path check (Windows)` — production-code analog Plan 35-03 mirrors for the `suggested_flag` UNC strip in `query_ext.rs::query_path`.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **Plan 34-08a Unix env-filter wiring in `crates/nono-cli/src/exec_strategy.rs`** — the call-site shape Plan 35-01 mirrors. Locate the `should_skip_env_var`-style filter call inside the Unix child-process env-block construction; replicate the shape inside the Windows analog in `exec_strategy_windows/`.
- **`crates/nono/src/capability.rs` / `crates/nono/src/sandbox/linux.rs`** — Landlock ruleset construction pattern; Plan 35-02's pre-create hunk lands in `profile_runtime.rs` BEFORE the ruleset is constructed (so the directory exists by the time Landlock evaluates the filesystem access rules).
- **Commit `400f8c90` production-code UNC strip** — Plan 35-03 mirrors the strip shape for `suggested_flag`. Read the commit body for the exact UNC-prefix detection (`starts_with(r"\\?\")` or `starts_with(OsStr::new(r"\\?\"))` per path-component-safe pattern) + strip semantics.
- **`profile_cmd.rs::profile_to_json` (line 1041) + `::diff_to_json` (line 1777)** — JSON emission helpers; the format!("{:?}") sites are at lines 1056 + 1303. Drop-in serde-driven Map insertion is the fix.

### Established Patterns
- **D-19 cherry-pick trailer (verbatim 6-line shape)** — Plan 35-02 only. Cite `bdf183e9` upstream commit + lowercase 'a' in `Upstream-author:`. Smoke check: `git log --format='%B' main~1..main | grep -c '^Upstream-commit: '` equals 1.
- **D-20 manual-replay shape** — Plan 35-01. Commit body documents what was ported from Plan 34-08a (Unix wiring) + upstream `1b412a7` (env-filter surface) and why straight cherry-pick was infeasible (Windows ExecConfig + PEB env-block construction has no upstream analog).
- **Phase 22 Windows-test gating pattern** — `#[cfg(target_os = "windows")]` for Windows-only tests (D-35-B3 empty-allow fail-closed test); `#[cfg(target_os = "linux")]` for Linux Landlock integration test (D-35-D3).
- **`serde_json::to_value` Map insertion for Option<…>** — restored shape from upstream `f3e7f885` for `signal_mode` and all other `Option<…>` security fields in profile JSON emission (D-35-C2 + D-35-C3).
- **Cross-target clippy gate (Phase 25 CR-A lesson)** — load-bearing for Plan 35-02 (Linux-only Landlock hunk).

### Integration Points
- **Plan 35-01 ↔ Plan 34-08a Unix wiring** — Windows wiring shape must compose with the cross-platform `ExecConfig.allowed_env_vars` / `denied_env_vars` fields Plan 34-08a defined. No new field; no field-rename; just add the Windows-side consumer.
- **Plan 35-02 ↔ Phase 37 Plan 25-01 RESL backends** — both phases land Linux-only code paths; Plan 35-02's Landlock pre-create runs BEFORE the supervisor's RESL backend wiring (when Phase 37 lands). No code coupling, but plan-close ordering for the Linux host validation matters — Plan 35-02 lands first, then Phase 37 Plan 25-01 verifies the RESL backends compose with the pre-created profiles directory.
- **Plan 35-03 JSON shape fix ↔ Phase 36 REQ-PORT-CLOSURE-02 deprecated_schema port** — REQ-PORT-CLOSURE-02 will restructure JSON schema with canonical sections (`groups`, `commands.{allow,deny}`, `filesystem.{deny,bypass_protection}`). Plan 35-03's `serde_json::to_value` Map insertion shape should be future-compatible with the canonical sections (i.e., omit-when-None semantics already match upstream's canonical schema; no rework expected at Phase 36).
- **Phase 35 close ledger** — Plan 35-03 SUMMARY appends a closure section to `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/deferred-items.md` flipping the 5 P34-DEFER-* entries (D-35-D4). Phase 34's directory remains the source of truth for the deferred-items ledger; Phase 35's per-plan SUMMARY files describe what Phase 35 did, not where the deferrals live.

</code_context>

<specifics>
## Specific Ideas

- **Three plans, one per REQ, wave-parallel** (D-35-A2 + D-35-A3) — user preferred the per-REQ traceability over a 2-by-platform split or a single combined plan. Mirrors Phase 34 D-34-A1 discipline.
- **Production-code UNC strip over test gating** (D-35-C1) — user explicitly rejected the Phase 22 `#[cfg(not(target_os = "windows"))]` gating shape and the Windows-specific test variant. The UX bug (suggested flags containing untypeable `\\?\C:\…`) was the deciding factor — same framing as commit `400f8c90` for the production-code analog.
- **Full audit of `format!("{:?}")` JSON-emission sites in `profile_cmd.rs`** (D-35-C3) — user rejected fixing only the two flagged tests. P34-DEFER-10-1's hypothesis about Plan 34-08b or 34-09 re-introducing the Debug fallback warrants a full sweep to close the regression class.
- **D-34-E1 inversion as its own decision row (D-35-A1)** — user rejected inline carve-out and re-scoping D-34-E1 retroactively. The new decision row at phase level is the cleanest audit shape for the inversion.
- **Surgical retrofit posture for REQ-01** (D-35-B4) — user explicitly rejected the audit-event retrofit. "Every retrofit becomes load-bearing surface" framing from D-34-B2.
- **Phase 34 close-gate inherited verbatim** (D-35-D2) — user rejected trimming macOS clippy or any other gate step. Predictability across phases > marginal cycle-time savings.

</specifics>

<deferred>
## Deferred Ideas

- **REQ-PORT-CLOSURE-05 (P34-DEFER-08b-1 + 08b-2)** — `b5f0a3ab` deep ExecConfig refactor + `bbdf7b85` escape-quote pipeline rider — Phase 36. Locked in REQUIREMENTS.md Traceability table. PROJECT.md line 19 has stale 08b-2 reference but ROADMAP + REQUIREMENTS authoritative.
- **`run_nono` integration tests for Windows env-filter (REQ-01)** — host-blocked by `dirs::home_dir()` Windows test-harness gap. Defer integration-test coverage to Phase 37/38 (Linux/macOS host) where Plan 25-01 + Plan 26-02 also run.
- **Audit-event emission for env-filter outcomes on Windows** — D-35-B4 keeps Phase 35 surgical. If audit visibility for env filtering becomes a cross-platform requirement, it's a new phase with its own design (cross-platform audit shape + RejectStage discrimination + ledger emission).
- **Structural regression test linting `format!("{:?}")` in any `*_to_json` helper** (rejected option for D-35-C3) — would lock the invariant via AST walker / syn-based test. Too heavy for Phase 35 quick-win shape; consider if the regression class re-opens after Phase 35 closes.
- **Proptest-driven env-filter semantics test** (rejected option for D-35-B3) — would generate `(allow, deny, env)` triples. Adds proptest setup cost to a quick-win plan. Reconsider if env-filter logic grows complexity in later milestones.
- **`nono completion` MSI installer integration, `--allow-connect-port` ↔ WFP composition, `nono learn` Windows ETW deprecation routing** — all carried forward as deferred from Phase 34 (D-34 deferred section). Phase 35 does not pick them up.
- **PROJECT.md line 19 stale-reference cleanup** — handled by `/gsd-progress` at Phase 35 close (Claude's discretion in D section); not a plan-level task.

### Reviewed Todos (not folded)

None — no pending todos surfaced for Phase 35 scope (validated against the absence of TODO_MATCHES in init; `gsd-sdk query todo.match-phase 35` not run because no `.planning/todos/` artifact exists per scout).

</deferred>

---

*Phase: 35-UPST3-closure quick wins*
*Context gathered: 2026-05-12*
