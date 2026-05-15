# Phase 41: CI cleanup + v24 broker code-review closure - Context

**Gathered:** 2026-05-15
**Status:** Ready for planning

<domain>
## Phase Boundary

Reset every CI lane to green and clear the v24 Windows broker code-review backlog so Phases 42 + 43 inherit a clean baseline.

Specifically this phase:
- Resolves the 33 Linux/macOS Clippy errors enumerated in `.planning/PHASE-41-TRACKER.md` (API migration + ~14 dead-code orphans + `std::env::*` → `EnvVarGuard` + unreachable expression + sundry).
- Resolves the 5 Windows CI job failures (Build, Integration, Regression, Security, Packaging) — MSI validator `-BrokerPath` mismatch, `windows_run_block_net_blocks_probe_connection` + `_through_cmd_host`, env_vars parallel flake, etc.
- Closes the 4 v24 Windows broker code-review todos (CR-01 FFI mapping, CR-02 null handle, CR-03 empty list, CR-04 Job-object test skip policy).
- Resets the baseline-aware CI gate (`.planning/templates/upstream-sync-quick.md` baseline SHA + SUMMARY frontmatter convention doc + STATE.md `## Deferred Items` cleanup) to the Phase 41 close SHA.

Out of scope: anything that's not a pre-existing CI red on baseline `a72736bb` or a v24 broker CR todo. New capabilities belong in other phases.

7 requirements: REQ-CI-01, REQ-CI-02, REQ-CI-03, REQ-BROKER-CR-01, REQ-BROKER-CR-02, REQ-BROKER-CR-03, REQ-BROKER-CR-04.

</domain>

<decisions>
## Implementation Decisions

### Sub-plan structure & ordering

- **D-01: API migration sub-plan lands FIRST.** Plan 41-01 ships the `CapabilityRequest::path` → `HandleTarget::FilePath` migration (14 call sites in `crates/nono-cli/src/exec_strategy.rs`) ahead of every other sub-plan. **Rationale:** Phase 37 (parallel) needs to rebase on this migration per `.planning/ROADMAP.md` § Sequencing Rationale — landing it first unblocks Phase 37's API-migration coordination point.
- **D-02: 7-plan layout, one per error class.** Tracker shape from `.planning/PHASE-41-TRACKER.md` § Suggested phase structure, with broker CR todos slotted as two additional plans:
  - **Plan 41-01** — API migration (`CapabilityRequest::path` → `HandleTarget::FilePath`, 14 sites, research-led).
  - **Plan 41-02** — Unix simple (dead-code dispositions + unreachable expression + `disallowed_methods` → `EnvVarGuard` migration + sundry residuals).
  - **Plan 41-03** — Win MSI validator (`scripts/validate-windows-msi-contract.ps1:115` `-BrokerPath` parameter threading).
  - **Plan 41-04** — Win block-net probe triage (`crates/nono-cli/tests/env_vars.rs:811, 959`, research-led).
  - **Plan 41-05** — env_vars parallel flake (`windows_run_redirects_profile_state_vars_into_writable_allowlist`).
  - **Plan 41-06** — broker hygiene CR-01 + CR-02 + CR-03 (bindings/c FFI remap + null-handle reject + empty-list reject).
  - **Plan 41-07** — broker CR-04 + baseline reset close gate (SKIP→FAIL + build.rs + `upstream-sync-quick.md` baseline SHA + SUMMARY frontmatter conventions + STATE.md `## Deferred Items` cleanup).
- **D-03: Two plans for broker CR todos (41-06 + 41-07).** CR-01/02/03 share the bindings/c + broker code area = Plan 41-06. CR-04 is a CI-signal-quality decision that pairs naturally with the baseline reset close gate = Plan 41-07. Maps directly to REQ-CI-03 SC#3 ("STATE.md `## Deferred Items` cleared of v24 CR-A class entries").
- **D-04: Explicit research pass before planning for Plans 41-01 and 41-04.**
  - **41-01 research scope:** Read upstream patch / `HandleTarget::FilePath` definition. Migrate ONE call site as a spike before bulk-applying to the remaining 13. Surface API migration as a "significant API surface change" candidate in CONTEXT (per tracker acceptance criterion 6) if the shape is deeper than a field rename.
  - **41-04 research scope:** Read `windows_run_block_net_blocks_probe_connection` + `_through_cmd_host` probe-fixture code path. Reproduce locally on the Windows host to identify why the probe never runs (runtime probe-fixture issue, broker-spawn path, network filter wiring, or fixture build issue) — root cause TBD per tracker hypothesis.
  - Research output feeds into the corresponding PLAN.md task list.

### Dead-code disposition policy

- **D-05: Investigate-first, default to wire-up if a Windows-only callsite exists.** For each of the ~14 orphans (esp. the 17 audit_ledger.rs functions), per-function:
  1. Grep for symbol across all `.rs` files including `exec_strategy_windows/` + Windows-gated tests + `crates/nono-shell-broker/`.
  2. If a Windows callsite exists, the cfg gating is wrong — fix the gating so the function is visible on non-Windows targets, OR add `#[cfg(target_os = "windows")]` to the function itself so non-Windows clippy sees it correctly.
  3. If truly no callsite exists, delete.
- **D-06: Cross-target verification standard before deleting.** `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` + `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` run from the Windows host before each delete-class commit. macOS cross-target clippy may rely on CI runner if the local cross-toolchain is unavailable, but Linux is non-negotiable per memory `feedback_clippy_cross_target`.
- **D-07: Commit body granularity — one commit per disposition class with table.** Plan 41-02 ships THREE commits:
  - `chore(41-02): delete truly-unused orphans` — table in body listing each function + grep evidence proving zero callsites.
  - `chore(41-02): wire-up audit infrastructure via cfg-gate fix` — table listing each function + the cfg-gate change that makes it visible on non-Windows OR makes it explicitly Windows-only.
  - `chore(41-02): preserve as Windows-only via cfg(target_os = "windows")` — table listing each function + the cfg attribute added.
- **D-08: `test_env.rs:343,344` disallowed-methods Drop fix — per-file `#[allow]` with rationale.** Add `#[allow(clippy::disallowed_methods)]` at the `EnvVarGuard::Drop` impl block with a 2-line comment explaining "this IS the abstraction; clippy lint applies to consumers". Mirrors how `unsafe` code is fenced — the primitive itself, not consumers. NOT a restructure into a private helper (would multiply `#[allow]` attributes without architectural gain).

### CR-01 FFI mapping (BrokerNotFound)

- **D-09: Remap `NonoError::BrokerNotFound` to existing `NonoErrorCode::ErrSandboxInit` (-6).** Lowest blast radius: no enum addition, no `bindings/c/include/nono.h` ABI surface change. `ErrSandboxInit` already covers "sandbox init failed" which is semantically what `BrokerNotFound` means at the supervisor boundary. Edit `bindings/c/src/lib.rs:138` to change the match arm; update the surrounding Phase-31-D-07 doc comment to clarify the variant is reused for broker-discovery failures (delete the "ErrPathNotFound — same semantic class as PathNotFound" rationale; replace with "broker discovery is a supervisor-init failure").
- **D-10: Update `bindings/c/include/nono.h` doc-comment only; downstream lockstep deferred to follow-up if needed.** Plan 41-06 updates the C-header doc-comment to reflect the remap. nono-py (`../nono-py/`) and nono-ts (`../nono-ts/`) only need a coordinated change if their bindings map by integer value (`-1 → FileNotFoundError`, `-6 → SandboxInitError`). Plan 41-06 includes a manual verification check on those bindings; if either repo IS mapping by value, file a follow-up todo to update them — do NOT block Phase 41 close on cross-repo work.
- **D-11: Plan 41-06 owns 3 new tests + downstream verification check.**
  - Broker argv unit test (CR-02): `--inherit-handle 0x0` → `SandboxInit` error + non-zero exit.
  - Broker argv unit test (CR-03): no `--inherit-handle` flags → `SandboxInit` error + non-zero exit (consistent with CR-03 (c) reject-empty-list).
  - FFI mapping test (CR-01): `NonoError::BrokerNotFound` maps to `ErrSandboxInit` (-6), not `ErrPathNotFound` (-1).
  - Manual verification check: confirm nono-py + nono-ts error-code interpretation unaffected.
- **D-12: CR-03 disposition = (c) reject empty `--inherit-handle` list in argv parser.** Mirrors CR-02's pattern — the broker parser becomes the consistent enforcement boundary for both "null handle" and "empty list". The existing broker test at `crates/nono-shell-broker/src/main.rs` ~line 489 (`an empty inherit-handle list is the most-restrictive`) flips from PASS-on-no-handles to assert-SandboxInit-error. Plan 31-02 SUMMARY's "empty list = most-restrictive" claim becomes correct-by-construction-rejected. CR-03 production path was structurally unreachable (Verifier note); this hardens the boundary regardless.

### CR-04 Job-object test skip policy

- **D-13: Convert silent-SKIP to FAIL when broker artifact missing — option (c).** `crates/nono-cli/src/exec_strategy_windows/launch.rs` test `broker_launch_assigns_child_to_job_object`: replace the `eprintln!` SKIP branch with `panic!("nono-shell-broker.exe missing at <path>; pre-build with `cargo build -p nono-shell-broker --release` before running this test")`. Highest CI signal quality — no false-PASS class possible. STATE.md `## Deferred Items` clears the v24 CR-A class entry per REQ-CI-03 SC#3.
- **D-14: `build.rs` triggers broker pre-build on Windows.** Add (or extend existing) `crates/nono-cli/build.rs` to invoke `cargo build -p nono-shell-broker --release --target x86_64-pc-windows-msvc` when `target_os = "windows"`. Pre-test broker availability becomes automatic; belt-and-suspenders with the FAIL assertion. Cost: longer first-run test compile on a clean checkout, acceptable trade-off given the CI signal-quality gain.

### Phase close gate

- **D-15: Draft PR opened early; CI continuous; close gate verifies green on PR head.** Plan 41-01 lands → draft PR opened against `main`. Each subsequent plan (41-02..41-07) pushes commits to that same branch. CI runs on every push. Phase 41 close gate: all 7 CI lanes (Linux Clippy + macOS Clippy + 5 Windows jobs) green on PR head + zero `success → failure` transitions vs the pre-cleanup baseline `a72736bb`. `/gsd-verify-phase 41` runs the green-lane check before close.
- **D-16: Plan 41-07 final task = baseline reset, three commits.**
  - `docs(41): reset baseline-aware CI gate to Phase 41 close SHA` — updates `.planning/templates/upstream-sync-quick.md` baseline SHA.
  - `docs(41): document skipped_gates_load_bearing vs _environmental convention` — adds the SUMMARY frontmatter convention block to the top of Phase 41's SUMMARY for Phase 43's inheritance per REQ-CI-03 SC#2.
  - `docs(41): clear v24 CR-A deferred items from STATE.md` — REQ-CI-03 SC#3.

### Folded Todos

The four `v24-cr-*` todos in `.planning/todos/pending/` were already mapped to Phase 41 via their frontmatter `resolves_phase: 41`. All four are folded into scope:

- **CR-01** (`v24-cr-01-broker-not-found-ffi-mapping.md`) → Plan 41-06, decision D-09 + D-10 + D-11.
- **CR-02** (`v24-cr-02-broker-null-handle-validation.md`) → Plan 41-06, test in D-11.
- **CR-03** (`v24-cr-03-broker-empty-handle-list-path.md`) → Plan 41-06, decision D-12.
- **CR-04** (`v24-cr-04-job-object-test-skip-policy.md`) → Plan 41-07, decision D-13 + D-14.

### Claude's Discretion

- Mechanical implementation details within each plan's task list (e.g., exact commit ordering within Plan 41-02 dead-code dispositions, choice of greppable test asserts vs structured match patterns) are left to the planner/researcher.
- CR-02 implementation specifics: planner picks whether the null-handle reject lives in the same match arm as the hex parser or as a separate post-parse validation step. Both are equivalent.
- Exact `build.rs` invocation shape (cargo subprocess vs Cargo's `xtask` pattern vs a `[dev-dependencies]` workaround) is a Plan 41-07 implementation detail.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase intent & error inventory

- `.planning/PHASE-41-TRACKER.md` — Full error categorization (33 Linux/macOS Clippy errors + 5 Windows CI job failures). Includes per-site file:line refs and root-cause hypotheses. THE primary spec for "what to fix".
- `.planning/ROADMAP.md` § Phase 41 — Goal + success criteria + dependencies + sequencing rationale (Phase 37 parallel coordination point).
- `.planning/REQUIREMENTS.md` § CI-CLEAN + § BROKER-CR — 7 requirements with acceptance criteria. REQ-CI-01..03 + REQ-BROKER-CR-01..04.

### v24 broker code-review todos

- `.planning/todos/pending/v24-cr-01-broker-not-found-ffi-mapping.md` — CR-01 source + suggested fix.
- `.planning/todos/pending/v24-cr-02-broker-null-handle-validation.md` — CR-02 source + acceptance gate.
- `.planning/todos/pending/v24-cr-03-broker-empty-handle-list-path.md` — CR-03 source + (a)/(b)/(c) options.
- `.planning/todos/pending/v24-cr-04-job-object-test-skip-policy.md` — CR-04 source + (a)/(b)/(c) options.

### Code surfaces touched by this phase

- `crates/nono-cli/src/exec_strategy.rs` — API migration sites at lines 2662, 2684, 2690, 2696, 2705, 2710, 2717, 2729, 2742, 2757, 2763, 2781, 2794, 2809; unreachable expression at 1930; dead-code orphans.
- `crates/nono-cli/src/audit_ledger.rs` — 17 orphan functions (largest single dead-code investigation surface).
- `crates/nono-cli/src/test_env.rs:343, 344` — `disallowed_methods` self-reference fix site.
- `crates/nono-cli/tests/env_vars.rs:811, 959` — block-net probe failures (REQ-CI-02).
- `crates/nono-cli/src/exec_strategy_windows/launch.rs` — `broker_launch_assigns_child_to_job_object` (CR-04 fix site).
- `crates/nono-shell-broker/src/main.rs` — argv parser at ~line 87 (`--inherit-handle` handling, CR-02 + CR-03 fix site); existing test at ~line 489 to update.
- `bindings/c/src/lib.rs:138` — `BrokerNotFound` → `ErrPathNotFound` mapping (CR-01 fix site).
- `bindings/c/src/types.rs:158, 168` — `NonoErrorCode` enum (target for CR-01 remap).
- `bindings/c/include/nono.h` — auto-generated header (doc-comment updates flow through cbindgen build).
- `scripts/validate-windows-msi-contract.ps1:115` — MSI validator `-BrokerPath` parameter (REQ-CI-02 fix site).

### Baseline / process surfaces

- `.planning/templates/upstream-sync-quick.md` — Baseline SHA + skipped-gates convention; reset target for REQ-CI-03 SC#1+SC#2.
- `.planning/STATE.md` § Deferred Items — v24 CR-A class entries to clear (REQ-CI-03 SC#3).

### Cross-phase conventions inherited

- `CLAUDE.md` § "Lazy use of dead code" — No `#[allow(dead_code)]` without explicit justification (REQ-CI-01 SC#4 enforcement source).
- Memory `feedback_clippy_cross_target` (Phase 25 CR-A regression lesson) — Cross-target clippy required for cfg-gated Unix code.
- Memory `project_workspace_crates` — Workspace has 5 crates; FFI variant additions cascade to each `Cargo.toml`. (NOT triggered here — D-09 uses an existing variant.)
- ROADMAP § Cross-Phase Invariants — CLAUDE.md "lazy use of dead code", cross-target clippy mandatory.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **`EnvVarGuard`** (`crates/nono-cli/src/test_env.rs`) — The canonical abstraction for env-var scope management in tests. Plan 41-02's `disallowed_methods` migration uses the EXISTING `EnvVarGuard::remove()` API for the 2 site fixes (lines outside the Drop impl); inside the Drop impl, D-08 fences the lint via per-file `#[allow]` because EnvVarGuard IS the abstraction.
- **`NonoErrorCode::ErrSandboxInit`** (`bindings/c/src/types.rs:168`) — Existing FFI variant already used for `LabelApplyFailed` and `SandboxInit` mappings; CR-01 reuses it for `BrokerNotFound` per D-09.
- **Broker argv parser** (`crates/nono-shell-broker/src/main.rs` line 87+) — Already returns `NonoError::SandboxInit` for parse failures; CR-02 + CR-03 extend the same error class consistently.

### Established Patterns

- **CR-A atomic-commit hygiene** (PR #2 precedent) — One commit per fix-class. Plan 41-02's three-commit disposition (delete / wire-up / preserve-Windows-only) follows this pattern.
- **D-19 cherry-pick trailer block** — NOT applicable here. Phase 41 is fork-internal cleanup, not upstream-sync; no `Upstream-commit:` trailers required.
- **Memory `feedback_clippy_cross_target`** — Run `cargo clippy --workspace --target x86_64-unknown-linux-gnu` from Windows host on every Linux-touching commit. Plan 41-02's verification standard codifies this per D-06.
- **Phase 31 D-07 doc-comment fingerprint** — `bindings/c/src/lib.rs:132-138` carries the rationale block for the current (incorrect) BrokerNotFound mapping; D-09 rewrites this block, not just the match arm.

### Integration Points

- **Phase 37 parallel coordination** — Plan 41-01 (API migration) MUST land before Phase 37 rebases. ROADMAP § Sequencing Rationale: "Phase 37 should rebase on Phase 41's API-migration sub-plan once it lands."
- **Phase 43 baseline inheritance** — Plan 41-07's baseline reset (D-16) becomes the new SHA in `.planning/templates/upstream-sync-quick.md`. Phase 43 cherry-picks will gate against this SHA per REQ-CI-03 + ROADMAP § Cross-Phase Invariants.
- **nono-py / nono-ts language bindings** — `bindings/c/src/lib.rs` changes flow through cbindgen → `bindings/c/include/nono.h`. Downstream repos (`../nono-py/`, `../nono-ts/`) consume the header. CR-01 doc-comment update happens here; downstream verification check per D-10.
- **Draft-PR-as-continuous-CI workflow** (D-15) — Plan 41-01 lands locally → draft PR opened → subsequent plans push to that branch. The PR is the close-gate signal source.

</code_context>

<specifics>
## Specific Ideas

- **CR-03 (c) "reject empty list" disposition is preferred over (a) "doc-only" or (b) "broker guard"** specifically because (b)'s "default-inherit" semantics are the OPPOSITE of "most-restrictive" (which was the original Plan 31-02 SUMMARY claim). Choosing (c) makes the broker parser the consistent enforcement boundary for both null-handle and empty-list inputs — Plan 31-02's SUMMARY claim becomes correct-by-construction-rejected rather than correct-by-runtime-error.
- **`build.rs` for broker pre-build (D-14)** specifically because relying on a Makefile target or CONTRIBUTING doc puts the burden on developer memory; `build.rs` makes it automatic. Acceptable trade-off: longer first-run compile on clean checkout.
- **Three commits for Plan 41-02 dead-code (D-07)** specifically because the disposition CLASS (delete / wire-up / preserve-Windows-only) is the natural review unit — a reviewer can mentally classify "is this disposition correct?" per class, scan the table in the body, and approve or flag. Per-function commits would multiply git-log noise without aiding review.

</specifics>

<deferred>
## Deferred Ideas

- **nono-py / nono-ts downstream FFI mapping coordination** — If `../nono-py/` or `../nono-ts/` map error codes by integer VALUE (not just stringify last-error), CR-01's remap from `-1 → -6` requires coordinated PRs there. Plan 41-06 owns the verification check (D-10); if downstream IS affected, file a follow-up todo to land those PRs post-Phase-41 close.
- **`ErrBrokerMissing` dedicated FFI variant** — Considered as option (b) for CR-01 but rejected in favor of reusing `ErrSandboxInit` (D-09). If a future phase wants to refactor the FFI error-code scheme to "one variant per distinct error class", `ErrBrokerMissing` would be one of several additions. Not Phase 41 scope.
- **CR-02 implementation specifics** (planner discretion per Claude's Discretion above) — null-handle reject in same match arm vs separate post-parse validation step. Whichever the planner picks must keep the test from D-11 passing.

### Reviewed Todos (not folded)

None — all 4 v24-cr-* todos that matched Phase 41 (via frontmatter `resolves_phase: 41`) were folded into scope per Folded Todos above.

</deferred>

---

*Phase: 41-CI-cleanup-v24-broker-code-review-closure*
*Context gathered: 2026-05-15*
