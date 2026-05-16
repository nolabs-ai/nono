# Phase 41: CI cleanup + v24 broker code-review closure - Research

**Researched:** 2026-05-15
**Domain:** Rust workspace CI hygiene + Windows broker FFI hardening + CI gate process
**Confidence:** HIGH (every claim below is verified against source code and CONTEXT.md; no `[ASSUMED]` knowledge claims)

## Summary

Phase 41 is mechanical fork-internal cleanup. CONTEXT.md has locked the 7-plan layout, dispositions, FFI remap target, and all decision points. The research focus, per CONTEXT D-04, is to surface the **technical specifics** each sub-plan needs from a code inspection of the actual file:line sites:

1. **Plan 41-01 API migration is a *deprecated-field migration*, NOT a deeper API change.** `CapabilityRequest::path: PathBuf` carries `#[deprecated(note = "use HandleTarget::FilePath via the new kind/target fields")]` since Phase 18 (AIPC-01). The new shape adds `kind: HandleKind` (defaults to `File`) and `target: Option<HandleTarget>` (defaults to `None`). The migration is a **read-pattern change at the 14 sites**: instead of `request.path` (which warns on the deprecated field), construct a helper `request_path(&request) -> &Path` that extracts from `target` when `Some(HandleTarget::FilePath { path })` and falls back to `&request.path` for Phase-11-shaped requests. The 14 sites are all inside `crates/nono-cli/src/exec_strategy.rs::handle_capability_message`'s decision tree.
2. **Plan 41-04 (block-net probe failure) has a strong candidate root cause from source inspection.** `--dangerous-force-wfp-ready` is `#[cfg(debug_assertions)]` (`cli.rs:1638`). If the test runs against a **release-mode** `nono` binary, clap rejects the unknown flag, the probe never spawns, and the test's assertion that output contains `"connect failed"` or `"exit code 42"` fails. The tracker's diagnostic ("output is just the `nono v0.X.Y` banner") is consistent with clap rejecting unknown args. Plan 41-04 verification: build mode of `nono_bin()` in CI matches the build profile of the test crate.
3. **Plan 41-02 dead-code dispositions: the audit_ledger.rs module is a self-contained orphan.** `compute_session_digest`, `append_session`, `verify_session_in_ledger`, `LedgerLock::acquire`, etc. are referenced ONLY inside `audit_ledger.rs` itself (and its `#[cfg(test)] mod tests`). No call site exists in `exec_strategy_windows/`, `supervisor.rs`, or anywhere else in the workspace. `record_capability_decision` in `audit_integrity.rs:217` IS called from `exec_strategy_windows/supervisor.rs:1832` — that's the one orphan that needs cfg-gating, not deletion.

**Primary recommendation:** Treat CONTEXT.md decisions as locked. Each sub-plan's task list mostly writes itself from the file:line evidence below. Two areas need a spike: (1) Plan 41-01 — migrate ONE site, verify Clippy + tests, then bulk-apply; (2) Plan 41-04 — confirm the cfg(debug_assertions) hypothesis by inspecting the CI workflow build profile (no test runs required).

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-01: API migration sub-plan lands FIRST.** Plan 41-01 ships the `CapabilityRequest::path` → `HandleTarget::FilePath` migration (14 call sites in `crates/nono-cli/src/exec_strategy.rs`) ahead of every other sub-plan. Phase 37 (parallel) rebases on this migration.
- **D-02: 7-plan layout, one per error class.** Plans 41-01 through 41-07 are locked (see Sub-Plan Briefs below).
- **D-03: Two plans for broker CR todos (41-06 + 41-07).** CR-01/02/03 share the bindings/c + broker code area = Plan 41-06. CR-04 is a CI-signal-quality decision that pairs with the baseline reset close gate = Plan 41-07.
- **D-04: Explicit research pass before planning for Plans 41-01 and 41-04.** This document satisfies that requirement.
- **D-05: Investigate-first, default to wire-up if a Windows-only callsite exists** for each of the ~14 dead-code orphans.
- **D-06: Cross-target verification standard before deleting.** `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` from Windows host is non-negotiable per memory `feedback_clippy_cross_target`. Darwin target may fall back to CI runner if local cross-toolchain unavailable.
- **D-07: Commit body granularity — one commit per disposition class with table.** Plan 41-02 ships THREE commits: delete / wire-up / preserve-Windows-only, each with a table in the body listing functions + grep evidence + cfg-gate changes.
- **D-08: `test_env.rs` disallowed-methods Drop fix — per-file `#[allow]` with rationale.** The primitive itself, not consumers, is fenced. (Note: see `### Site Correction` under Plan 41-02 below — the lines have moved and the `#[allow]` may already be applied.)
- **D-09: Remap `NonoError::BrokerNotFound` to existing `NonoErrorCode::ErrSandboxInit` (-6).** Lowest blast radius; no enum addition, no `nono.h` ABI surface change.
- **D-10: Update `bindings/c/include/nono.h` doc-comment only; downstream lockstep deferred to follow-up if needed.** Plan 41-06 includes a manual verification check on `../nono-py/` and `../nono-ts/`.
- **D-11: Plan 41-06 owns 3 new tests + downstream verification check** (broker argv null-handle reject, broker argv empty-list reject, FFI mapping test).
- **D-12: CR-03 disposition = (c) reject empty `--inherit-handle` list in argv parser.** Existing test at `crates/nono-shell-broker/src/main.rs:493` (`parse_args_empty_inherit_handle_list_is_ok`) flips from PASS-on-no-handles to assert-`SandboxInit`-error.
- **D-13: Convert silent-SKIP to FAIL when broker artifact missing — option (c).** `crates/nono-cli/src/exec_strategy_windows/launch.rs` test `broker_launch_assigns_child_to_job_object`: replace `eprintln!` SKIP at lines 2450-2460 with `panic!`.
- **D-14: `build.rs` triggers broker pre-build on Windows.** Add invocation to existing `crates/nono-cli/build.rs`.
- **D-15: Draft PR opened early; CI continuous; close gate verifies green on PR head** + zero `success → failure` transitions vs pre-cleanup baseline `a72736bb`.
- **D-16: Plan 41-07 final task = baseline reset, three commits** — baseline SHA update + skipped-gates convention block + STATE.md `## Deferred Items` cleanup.

### Claude's Discretion

- Mechanical implementation details within each plan's task list (exact commit ordering inside Plan 41-02 dead-code dispositions, choice of greppable test asserts vs structured match patterns).
- CR-02 implementation: planner picks whether null-handle reject lives in the `--inherit-handle` match arm (post-parse) or as a separate post-parse validation step. Both are equivalent.
- Exact `build.rs` invocation shape (cargo subprocess vs Cargo's `xtask` vs `[dev-dependencies]` workaround).

### Deferred Ideas (OUT OF SCOPE)

- **nono-py / nono-ts downstream FFI mapping coordination** — if those repos map error codes by integer value, the `-1 → -6` remap requires coordinated PRs. Plan 41-06 verifies; if affected, file a follow-up todo, do NOT block Phase 41 close.
- **`ErrBrokerMissing` dedicated FFI variant** — rejected in favor of reusing `ErrSandboxInit`. Not Phase 41 scope.
- **CR-02 implementation specifics** — planner discretion per above.

</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| REQ-CI-01 | Linux/macOS Clippy lints resolved (33 errors) | Plan 41-01 API migration brief + Plan 41-02 dead-code/disallowed-methods/unreachable evidence |
| REQ-CI-02 | Windows CI jobs green (5 jobs: Build, Integration, Regression, Security, Packaging) | Plan 41-03 MSI validator brief + Plan 41-04 block-net probe root cause + Plan 41-05 parallel flake brief |
| REQ-CI-03 | Baseline-aware gate reset (template baseline SHA + SUMMARY conventions + STATE.md cleanup) | Plan 41-07 baseline-reset brief — template currently has NO baseline SHA section, so this is an additive change, not a find-replace |
| REQ-BROKER-CR-01 | Broker FFI not-found mapping to a clear NonoError variant | Plan 41-06 — `bindings/c/src/lib.rs:138` remap to `ErrSandboxInit` (-6) at `bindings/c/src/types.rs:168` |
| REQ-BROKER-CR-02 | Broker null-handle validation | Plan 41-06 — `crates/nono-shell-broker/src/main.rs:87-99` argv parser; reject when parsed value is 0 or `INVALID_HANDLE_VALUE` |
| REQ-BROKER-CR-03 | Broker empty-handle-list path handling (D-12: option c — reject) | Plan 41-06 — argv parser post-parse check after line 122; existing test at line 493 flips |
| REQ-BROKER-CR-04 | Job-object test skip policy (D-13: option c — FAIL) | Plan 41-07 — `crates/nono-cli/src/exec_strategy_windows/launch.rs:2450-2460` + `crates/nono-cli/build.rs` extension |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

These directives carry the same authority as locked decisions:

- **No `.unwrap()`/`.expect()` in production code.** Enforced by `clippy::unwrap_used`. Permitted only in test modules and doc examples via `#[allow(clippy::unwrap_used)]`.
- **No `#[allow(dead_code)]` without explicit justification.** REQ-CI-01 SC#4 enforcement source: "lazy use of dead code" rule. Either delete or wire-up the orphan.
- **Cross-target clippy required for cfg-gated Unix code** (memory `feedback_clippy_cross_target`). Windows-host workspace clippy alone is insufficient for Linux-touching plans — the Phase 25 CR-A regression lesson.
- **Workspace has 5 crates** (memory `project_workspace_crates`). CLAUDE.md still lists only 5 but historically said 3. The 5 are: `crates/nono`, `crates/nono-cli`, `crates/nono-proxy`, `crates/nono-shell-broker`, `bindings/c/` (nono-ffi). **NOT triggered for Phase 41** — D-09 reuses an existing FFI variant.
- **DCO sign-off required on every commit** (`Signed-off-by: <name> <email>`).
- **GSD workflow enforcement** (CLAUDE.md § GSD Workflow Enforcement). All edits go through GSD commands.
- **Fail-secure on errors.** Never silently degrade. Use `Result`, not panic, for expected failures (libraries should almost never panic). EXCEPTION: Plan 41-07 CR-04 uses `panic!` intentionally for the broker-test missing-artifact case — `panic!` here IS the fail-closed behavior for CI signal quality (CONTEXT D-13).

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Clippy lint resolution (Plans 41-01, 41-02) | Library/CLI (Rust workspace) | — | Cross-platform Rust code with cfg-gated branches; cross-target clippy is the verification surface |
| FFI error-code remap (Plan 41-06 CR-01) | nono-ffi (`bindings/c/`) | nono library (NonoError taxonomy) | The mapping function lives in the FFI shim layer; the library's `NonoError::BrokerNotFound` variant is unchanged |
| Broker argv hardening (Plan 41-06 CR-02 + CR-03) | nono-shell-broker (separate crate) | — | The broker is a Medium-IL helper binary; its argv parser is the only entry point and the correct enforcement boundary per Phase 31 design |
| MSI validator parameter (Plan 41-03) | Build/release tooling (`scripts/`) | — | PowerShell build script; outside the Rust workspace; no library/CLI changes |
| Block-net probe test (Plan 41-04) | nono-cli integration tests | nono-cli (CLI flag visibility) | Test failure may trace to `cfg(debug_assertions)` flag visibility; the fix is either test-side (build profile match) or product-side (promote the flag out of debug_assertions) |
| Parallel test flake (Plan 41-05) | nono-cli integration tests | nono-cli production code (`EnvVarGuard`) | Cross-process env-var contamination between parallel tests |
| Job-object test skip policy (Plan 41-07 CR-04) | nono-cli integration tests | nono-cli build script | Two-layer fix: panic on missing artifact + build.rs pre-builds artifact |
| Baseline reset (Plan 41-07) | Planning artifacts (`.planning/`) | — | Process tooling change; no code |

## Standard Stack

This is a fork-internal cleanup phase, not a feature-add phase. No new dependencies. All work uses the existing toolchain.

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| Rust | 1.77 (Edition 2021) | Workspace language | CLAUDE.md § Technology Stack |
| Cargo | bundled | Package + build | CLAUDE.md |
| clippy | bundled | Lint enforcement | `make ci` invokes `-D warnings -D clippy::unwrap_used` |
| windows-sys | 0.59 | Win32 API bindings (broker argv parser uses `HANDLE` type) | CLAUDE.md § Key Dependencies |
| `thiserror` | (existing) | `NonoError` enum definition site (no change in Phase 41) | CLAUDE.md § Error Handling |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `nono::test_env::EnvVarGuard` | internal | Drop-time env-var restore in tests | Plan 41-02 disallowed-methods migration — REQUIRED replacement for `std::env::set_var`/`remove_var` per `clippy.toml` |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `ErrSandboxInit` remap for `BrokerNotFound` | Add `ErrBrokerMissing` (-15) variant | Cross-binding lockstep PR cost; rejected per CONTEXT D-09 |
| `panic!` in CR-04 test on missing artifact | `#[ignore]` + `cargo test -- --ignored` opt-in | False-PASS class for unaware CI; rejected per CONTEXT D-13 |
| build.rs pre-build broker | `Makefile` target or CONTRIBUTING doc | Burden on developer memory; rejected per CONTEXT D-14 |

**Installation:** None. Phase 41 ships no new dependencies.

**Version verification:** Not applicable — no new package versions introduced.

## Architecture Patterns

### System Architecture Diagram

```
Source code changes ──┬──► Plan 41-01 (API migration, 14 sites in exec_strategy.rs)
                      ├──► Plan 41-02 (dead-code dispositions + disallowed-methods + unreachable + sundry)
                      ├──► Plan 41-03 (PowerShell MSI validator)
                      ├──► Plan 41-06 (broker FFI mapping + broker argv hardening)
                      └──► Plan 41-07 task 1+2 (broker test skip → FAIL + build.rs)

Test/CI changes    ──┬──► Plan 41-04 (block-net probe triage — root cause TBD post-research)
                     └──► Plan 41-05 (env_vars parallel flake fix)

Process changes    ──── Plan 41-07 task 3+4+5 (baseline reset to Phase 41 close SHA;
                                                SUMMARY frontmatter convention block;
                                                STATE.md ## Deferred Items cleanup)

All changes ──► single draft PR (D-15) → 7 CI lanes (Linux Clippy + macOS Clippy + 5 Windows jobs) green on PR head + zero new failures vs baseline `a72736bb` → /gsd-verify-phase 41 → merge
```

Component responsibilities map to the 7 sub-plans; see **Sub-Plan Briefs** below for per-plan file:line references.

### Recommended Project Structure

This is cleanup, not new structure. Existing structure honored verbatim:

```
crates/nono/src/supervisor/types.rs      # CapabilityRequest + HandleTarget (the migration target)
crates/nono-cli/src/exec_strategy.rs      # 14 migration sites + unreachable expression + audit_recorder field
crates/nono-cli/src/audit_ledger.rs       # 17 orphan functions (delete-class candidates)
crates/nono-cli/src/audit_integrity.rs    # record_capability_decision (wire-up class)
crates/nono-cli/src/test_env.rs           # EnvVarGuard (already has #[allow(clippy::disallowed_methods)])
crates/nono-cli/src/profile_runtime.rs    # env::set_var/remove_var without #[allow] — Plan 41-02 candidate
crates/nono-cli/build.rs                  # Extended in Plan 41-07 to pre-build broker on Windows
crates/nono-cli/tests/env_vars.rs         # Plan 41-04 + 41-05 fix sites
crates/nono-cli/src/exec_strategy_windows/launch.rs  # broker_launch_assigns_child_to_job_object (Plan 41-07)
crates/nono-shell-broker/src/main.rs      # argv parser (Plan 41-06 CR-02 + CR-03)
bindings/c/src/lib.rs                     # NonoError → NonoErrorCode mapping (Plan 41-06 CR-01)
bindings/c/src/types.rs                   # NonoErrorCode enum (target ErrSandboxInit = -6)
bindings/c/include/nono.h                 # Auto-generated header (doc-comment via cbindgen build)
scripts/validate-windows-msi-contract.ps1 # Plan 41-03 fix site
scripts/build-windows-msi.ps1             # Calls Get-WixDocumentForScope; requires -BrokerPath
.planning/templates/upstream-sync-quick.md  # Plan 41-07 baseline-reset target (additive change)
.planning/STATE.md                        # Plan 41-07 ## Deferred Items cleanup target
```

### Pattern 1: CapabilityRequest path-extraction helper

**What:** Add a private helper to `exec_strategy.rs` that extracts the path from a `CapabilityRequest` using the new shape with deprecated-field fallback. Replace the 14 `request.path` reads with calls to the helper.

**When to use:** Plan 41-01 mass migration.

**Example (verified against `crates/nono/src/supervisor/types.rs:101-145` for `HandleTarget` shape and `:153-196` for `CapabilityRequest` shape):**

```rust
// Suggested helper placement: top of handle_capability_message scope OR
// module-private in exec_strategy.rs above the supervisor loop.
//
// Reads the request's path using the AIPC-01 shape (target = Some(FilePath{path}))
// with fallback to the Phase-11 deprecated `path` field for wire-compat.
fn request_path(request: &nono::CapabilityRequest) -> &std::path::Path {
    use nono::HandleTarget;
    match &request.target {
        Some(HandleTarget::FilePath { path }) => path.as_path(),
        // Phase 11 wire shape: target was absent, kind defaulted to File.
        // The deprecated `path` field still carries the value. The
        // `#[allow(deprecated)]` on the struct definition (line 151 of
        // supervisor/types.rs) makes the field readable without a per-callsite
        // attribute, but reads through the helper localize the deprecation
        // surface to ONE place — once Phase 11 wire-shape is fully retired,
        // only this helper needs to change.
        _ => {
            #[allow(deprecated)]
            { &request.path }
        }
    }
}
```

**Then at each of the 14 sites:** replace `request.path.clone()` → `request_path(&request).to_path_buf()`, `&request.path` → `request_path(&request)`, and `request.path.display()` → `request_path(&request).display()`.

### Pattern 2: per-block `#[allow(clippy::disallowed_methods)]` fencing

**What:** When `std::env::set_var`/`remove_var` lives in code that IS the abstraction (not a consumer), fence the lint at the impl block, not at every call site.

**Status in this codebase:** `crates/nono-cli/src/test_env.rs:24` and `:56` ALREADY have `#[allow(clippy::disallowed_methods)]` with rationale comments. The CONTEXT D-08 fix may already be in place; the planner should verify the Clippy errors actually originate from `test_env.rs` (tracker said lines 343,344 but file is only 67 lines — see **Site Correction** under Plan 41-02 below).

**Real candidates** (verified via grep on 2026-05-15):
- `crates/nono-cli/src/profile_runtime.rs:331, 343, 344` — `EnvGuard` Drop impl inside `#[cfg(target_os = "linux")]` test block, NO `#[allow]` attribute, NOT covered by any existing fence.

### Pattern 3: Broker argv parser as enforcement boundary

**What:** The broker's `parse_args` (`crates/nono-shell-broker/src/main.rs:87-122`) returns `NonoError::SandboxInit(...)` for every malformed input. Extending it to reject null handles (CR-02) and empty handle lists (CR-03) keeps the parser as the single, consistent fail-closed boundary.

**Verified:** Lines 87-99 already accept `--inherit-handle <hex>` with hex parsing via `usize::from_str_radix(stripped, 16)`. Adding a post-parse check `if raw_value == 0 || raw_value == usize::MAX` is structurally the smallest change.

### Anti-Patterns to Avoid

- **Per-site `#[allow]` proliferation for `disallowed_methods`.** CONTEXT D-08 explicitly rejects this — fence at the abstraction block, not consumers. Already practiced in `test_env.rs:24, 56`.
- **Silent SKIP on missing test artifacts.** CONTEXT D-13 explicitly rejects this — CI false-PASS class. Use `panic!` to fail loudly.
- **Adding `#[allow(dead_code)]` to silence Plan 41-02 orphan warnings.** Forbidden by CLAUDE.md "lazy use of dead code" rule and REQ-CI-01 SC#4.
- **Adding a new `NonoErrorCode` variant for `BrokerNotFound`.** CONTEXT D-09 explicitly rejects this — cross-binding lockstep cost > reuse-existing benefit.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Env-var Drop-time restore in tests | A new ad-hoc EnvGuard | `crate::test_env::EnvVarGuard` | Already exists; `clippy.toml::disallowed-methods` points at it as the standard replacement |
| FFI error-code expansion | A new `NonoErrorCode::ErrBrokerMissing` variant | Reuse `NonoErrorCode::ErrSandboxInit (-6)` | CONTEXT D-09 cost/benefit; same semantic class |
| Custom broker prebuild script | Makefile target or doc-only "remember to build broker" | Extend `crates/nono-cli/build.rs` | CONTEXT D-14 makes pre-build automatic; eliminates developer-memory-burden |
| Path-extraction helper for `CapabilityRequest` | Inline `match &request.target { ... }` at all 14 sites | One private `request_path()` helper | Localizes the deprecation surface to one spot; the eventual cleanup (Phase 11 wire-shape retirement) touches one function not fourteen |

**Key insight:** Phase 41 is cleanup; resist the urge to "improve while I'm here". Each plan does ONE thing.

## Sub-Plan Briefs

Plan-by-plan technical brief for the planner. The sub-plan layout is locked by CONTEXT D-02; this section gives the planner the file:line evidence + spike-validated patterns to produce a tight task list.

### Plan 41-01 — API migration (`CapabilityRequest::path` → `HandleTarget::FilePath`)

**Locked first per CONTEXT D-01.** Phase 37 (parallel) rebases on this.

**API shape (verified from `crates/nono/src/supervisor/types.rs:101-196`):**

- `HandleTarget` is a `#[serde(tag = "type")]` tagged enum with 6 variants. `FilePath { path: PathBuf }` is the variant used here. Lines 103-145 define the enum.
- `CapabilityRequest` (line 153) carries the deprecated `path: PathBuf` field (line 163-164 with `#[deprecated(note = "use HandleTarget::FilePath via the new kind/target fields")]`), plus the new `kind: HandleKind` field (line 184, defaults to `File`) and `target: Option<HandleTarget>` (line 189, defaults to `None`).
- The struct carries `#[allow(deprecated)]` at line 151 — reads of `path` from within the struct's own definition compile silently. But reads from `exec_strategy.rs` trigger the deprecation warning that is firing in Linux/macOS clippy.

**Migration shape:** **Deprecated-field migration**, NOT a deeper API change. The 14 sites all read `request.path` in identical patterns:

- 7 sites: `path: request.path.clone(),` inside `DenialRecord { ... }` struct literals at lines 2662, 2696, 2729, 2742, 2763, 2781, 2794 (and one in the if-let arm at 2705).
- 5 sites: `request.path.display()` inside `format!`/`debug!`/`warn!` calls at lines 2684, 2690, 2710, 2717, 2757.
- 2 sites: `&request.path` parameter passes at lines 2684 (`overlapping_protected_root(&request.path, false, …)`) and 2710 (`ti.check_path(&request.path)`).
- Plus the **`open_path_for_access` call at lines 2808-2814** uses `&request.path` and `&request.access` together — this is OUTSIDE the 14 enumerated by the tracker but IS a deprecated-field read. The planner should grep `request\.path` inside `exec_strategy.rs` to confirm the exact count.

**Spike protocol (CONTEXT D-04):** Apply the helper pattern (see **Pattern 1** above) at ONE site (recommend 2662, the first occurrence in `handle_capability_message`). Run `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` from Windows host. If clippy clean for that site, bulk-apply.

**Significant API surface change?** No — per tracker acceptance criterion 6. The new `kind` + `target` fields default via `#[serde(default)]` so wire-compat with Phase-11-shaped requests is preserved. The migration is read-pattern only on the supervisor side; no upstream patch shape change.

**Cross-target verification (required, per D-06):**

```bash
cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used
cargo clippy --workspace --target x86_64-apple-darwin    -- -D warnings -D clippy::unwrap_used
```

**Risk areas:**

- `record_denial(denials, DenialRecord { path: request.path.clone(), ... })` — the inner `path` field on `DenialRecord` is a separate type, NOT the same `CapabilityRequest::path`. The helper return is `&Path`; `.to_path_buf()` is required to convert for the `DenialRecord::path: PathBuf` field. The spike must verify this compiles.
- `open_path_for_access(&request.path, &request.access, ...)` at line 2808-2814 — verify the function signature accepts `&Path` (a `&PathBuf` deref-coerces, but the helper returns `&Path` directly, no deref needed).

### Plan 41-02 — Unix simple (dead-code dispositions + `EnvVarGuard` migration + unreachable + sundry)

**Three commits per CONTEXT D-07.**

#### Dead-code inventory (verified via grep on 2026-05-15)

| Symbol | File:line of definition | Non-test callers found | Disposition class |
|--------|-------------------------|------------------------|-------------------|
| `AUDIT_LEDGER_FILENAME` | `audit_ledger.rs:15` | None outside `audit_ledger.rs` (only its own tests) | **DELETE** (the module's `pub(crate)` API has zero consumers) |
| `AUDIT_LEDGER_LOCK_FILENAME` | `audit_ledger.rs:16` | None | **DELETE** |
| `SESSION_DIGEST_DOMAIN` | `audit_ledger.rs:17` | None outside module | **DELETE** |
| `LEDGER_CHAIN_DOMAIN` | `audit_ledger.rs:18` | None outside module | **DELETE** |
| `LEDGER_HASH_ALGORITHM` | `audit_ledger.rs:19` | None outside module | **DELETE** |
| `SessionDigestPayload` | `audit_ledger.rs:22` | None outside module | **DELETE** |
| `ExecutableIdentityDigestPayload` | `audit_ledger.rs:39` | None outside module | **DELETE** |
| `LedgerRecord` | `audit_ledger.rs:45` | None outside module | **DELETE** |
| `LedgerLinkPayload` | `audit_ledger.rs:55` | None outside module | **DELETE** |
| `LedgerVerificationResult` | `audit_ledger.rs:63` | None outside module | **DELETE** |
| `compute_session_digest` | `audit_ledger.rs:73` | None outside module (tests inside module use it) | **DELETE** |
| `path_bytes` | (inside audit_ledger.rs) | None outside module | **DELETE** |
| `append_session` | `audit_ledger.rs:117` | None outside module | **DELETE** |
| `validate_ledger_session_id` | (inside audit_ledger.rs) | None outside module | **DELETE** |
| `append_locked` | (inside audit_ledger.rs) | None outside module | **DELETE** |
| `verify_session_in_ledger` | `audit_ledger.rs:217` | None outside module | **DELETE** |
| `LedgerLock::acquire` | (inside audit_ledger.rs) | None outside module | **DELETE** |
| `hash_ledger_link` | (inside audit_ledger.rs) | None outside module | **DELETE** |
| `audit_integrity::record_capability_decision` | `audit_integrity.rs:217` | **`exec_strategy_windows/supervisor.rs:1832`** | **WIRE-UP / cfg-gate fix** — Windows-only caller exists; the function needs `#[cfg(target_os = "windows")]` on the function itself (or the warning must be cfg-gated to non-Windows targets) |
| `exec_identity::NotApplicable` | `exec_identity.rs` (variant) | Investigate via grep — see "Open Questions" | **TBD** — needs disposition (likely Windows-only) |
| `exec_strategy.rs:376 audit_recorder field` | `exec_strategy.rs:376` (verified) | Field on `SupervisorRunArgs<'a>` struct; readers are `audit_recorder.is_some()` checks — Linux/macOS supervisor never reads the recorder | **TBD** — likely cfg-gate to Windows-only with `#[cfg_attr(not(target_os = "windows"), allow(dead_code))]` pattern, mirroring line 380's `allow_launch_services_active` precedent |
| `exec_strategy/env_sanitization.rs::validate_env_var_patterns` | `env_sanitization.rs:127` (verified pub(crate)) | `exec_strategy.rs:50` re-exports it; called by tests in same file (lines 311, 317, 325, 333, 339, 345) | **WIRE-UP / cfg-gate fix** — IS called, but the re-export at `exec_strategy.rs:50` may be the orphan; verify the cfg path |
| `exec_strategy/supervisor_linux.rs::kill_all` | `supervisor_linux.rs:1231` | Called inside same file at lines 1434, 1453 (tests) | **DELETE** non-test definition OR **WIRE-UP / cfg-gate fix** — if tests are the only consumers, it's a test-only function and should be `#[cfg(test)]` |
| `launch_runtime.rs::interactive_shell` | `launch_runtime.rs:170` (struct field) | Read at `supervised_runtime.rs:348`, `execution_runtime.rs:411`, and inside Windows code at multiple sites | **WIRE-UP / cfg-gate fix** — actually used; warning likely originates from a different unused-import path |
| `protected_paths.rs::sort_and_dedup_roots`, `paths_equal` | `protected_paths.rs:186, 276/281` | Called at `protected_paths.rs:32, 188, 379` (same file) | **WIRE-UP / cfg-gate fix** — module-internal helpers; if they're public/`pub(crate)` and tests don't exercise them on non-Windows, gate appropriately |
| `pty_proxy.rs::shutdown_attach_listener` | `pty_proxy.rs:364` | Investigate — grep showed no external callers | **TBD** — likely Windows-only or test-only |
| `rollback_session.rs::rollback_root_with_override` | `rollback_session.rs:51` | Investigate — grep showed no external callers | **TBD** — likely test-only or stale |
| `session.rs::session_log_path` | `session.rs:827` | `session_commands_windows.rs:402` | **WIRE-UP / cfg-gate fix** — Windows-only caller exists |

**Commit 1 (DELETE):** the 18 `audit_ledger.rs` symbols (the module is essentially a graveyard). The planner can either delete the file outright (if the test module inside it is also unused outside this file, which it appears to be) or gut the module to its single used surface. Verify via `git grep 'mod audit_ledger\|audit_ledger::'` in `crates/`. Expected post-delete shape: remove `mod audit_ledger;` from `crates/nono-cli/src/main.rs:10`.

**Commit 2 (WIRE-UP / cfg-gate fix):** `record_capability_decision` + `session_log_path` + others with Windows-only callers. Either:
- Apply `#[cfg(target_os = "windows")]` to the function itself (Linux/macOS clippy then doesn't see it at all), OR
- Apply `#[cfg_attr(not(target_os = "windows"), allow(dead_code))]` (Linux/macOS clippy sees it but tolerates the dead-code).

The first is cleaner; the second matches the existing precedent at `exec_strategy.rs:380` (`allow_launch_services_active`).

**Commit 3 (preserve as Windows-only):** any orphan that the investigation reveals is truly Windows-only (currently TBD pending Plan 41-02 spike).

#### `disallowed_methods` migration

##### Site Correction

The PHASE-41-TRACKER says `crates/nono-cli/src/test_env.rs:343,344` but the actual file is only **67 lines** and ALREADY carries `#[allow(clippy::disallowed_methods)]` at lines 24 and 56 with the exact rationale CONTEXT D-08 specifies ("This IS the safe wrapper around env var mutation."). The CONTEXT D-08 directive may have been **partially applied already**, or the tracker line numbers refer to a different historical commit.

**The actual `disallowed_methods` warnings on Linux** very likely originate from:

- `crates/nono-cli/src/profile_runtime.rs:331` — `std::env::set_var(key, value);` inside `EnvGuard::set` (test helper, inside `#[cfg(target_os = "linux")]` test mod). NOT covered by any `#[allow]`.
- `crates/nono-cli/src/profile_runtime.rs:343, 344` — `std::env::set_var(&self.key, val)` and `std::env::remove_var(&self.key)` inside the same `EnvGuard::Drop` impl. NOT covered.

**Recommended fix:** Apply the same D-08 pattern to `profile_runtime.rs`'s `EnvGuard` impl block — `#[allow(clippy::disallowed_methods)]` at the impl block with a 2-line rationale referencing `EnvVarGuard` as the canonical abstraction. OR (cleaner) replace `EnvGuard` in `profile_runtime.rs` with `use crate::test_env::EnvVarGuard` since they're functionally identical.

The planner should **grep with `cargo clippy --workspace --target x86_64-unknown-linux-gnu --message-format=json 2>&1 | grep disallowed_methods`** during the spike to confirm exact origin sites.

#### Unreachable expression (`exec_strategy.rs:1930`)

Line 1930 is `wait_for_child(child)` — the LAST expression in `fn wait_for_child_with_timeout` (or its parent function). Lines 1920-1928 form a `loop` with all branches that either `return Ok(status)`, `return Err(...)`, `continue`, or `sleep` (which restarts the loop iteration). The `loop` exits only via `return` — control flow proves `wait_for_child(child)` after the loop is unreachable.

**Fix:** Delete line 1930 (and any preceding blank line). The `loop` body has the type `()` after the change — if the function signature requires a `Result<WaitStatus>` return type, the `return`s inside the loop carry it. Verify the function signature compiles after deletion.

#### Sundry / fields-never-read

Per tracker "2+ misc — needs investigation". Planner runs the spike via clippy --message-format=json to enumerate exact sites, then dispositions per CONTEXT D-05 disposition tree.

**Cross-target verification (D-06):** Required on EVERY delete-class commit. The CR-A regression at `4665ae75` (Phase 40 Wave 1) shows the failure mode: Windows-host workspace clippy missed a `use std::path::{Path, PathBuf}` that was only used inside `#[cfg(target_os = "windows")]` blocks. Running `cargo clippy --workspace --target x86_64-unknown-linux-gnu` from the Windows host catches this class.

### Plan 41-03 — Win MSI validator (`-BrokerPath` parameter)

**One-file PowerShell fix.**

**Verified surfaces:**

- `scripts/build-windows-msi.ps1:12-13` declares `[Parameter(Mandatory = $true)] [string]$BrokerPath` — has been mandatory since Phase 31 Plan 04 (2026-05-09). Line 134-137 validates the path exists and resolves to absolute.
- `scripts/validate-windows-msi-contract.ps1:11-33` defines `function Get-WixDocumentForScope` accepting `$Scope`, `$Binary`, `$ServiceBinary` (default `""`). Lines 30-39 build `$buildArgs` hashtable, then **lines 39-41** invoke `& (Join-Path $PSScriptRoot "build-windows-msi.ps1") @buildArgs`. **The `$buildArgs` hashtable does NOT include `BrokerPath`**, so PowerShell throws "Cannot process command because of one or more missing mandatory parameters: BrokerPath" at invocation time.
- `validate-windows-msi-contract.ps1:115` is the call site that invokes `Get-WixDocumentForScope` for the machine scope.

**Fix shape (one of two patterns):**

1. **Add `BrokerPath` mandatory param to the validator and thread it through.** Modify `param(...)` block (top of `validate-windows-msi-contract.ps1`) to require `-BrokerPath`. Modify `Get-WixDocumentForScope` to accept `$BrokerPath` and add `$buildArgs["BrokerPath"] = $BrokerPath`. Update CI workflow YAML that invokes the validator to pass `-BrokerPath`.
2. **Construct a default broker path inside the validator.** If the broker binary is at a known path relative to `$BinaryPath` (e.g., `$BinaryPath`'s parent + `nono-shell-broker.exe`), the validator can compute it. Less brittle if the CI workflow doesn't need to know about brokers, but couples the validator to the build layout.

**Pattern (1) is preferred** — matches the precedent set by `$ServiceBinaryPath` (validator passes it through). Planner picks the exact invocation form; CONTEXT § Claude's Discretion permits this choice.

**Cross-reference:** Quick task `260513-f5n` already updated `docs/cli/development/windows-poc-handoff.mdx` for the same mandatory `-BrokerPath` shift. The validator was missed in that pass.

### Plan 41-04 — Win block-net probe triage

**Research-led per CONTEXT D-04.** This brief surfaces root-cause hypotheses ranked by source-evidence strength.

**Test bodies (verified):**

- `crates/nono-cli/tests/env_vars.rs:773` `windows_run_block_net_blocks_probe_connection` (and 916 `_through_cmd_host`) — both call `nono_bin().args(["run", "--allow", &allowed, "--dangerous-force-wfp-ready", "--block-net", "--workdir", &workdir, "--", &probe, "--connect-port", &port])`.
- Both assert `text.contains("connect failed") || text.contains("exit code 42")` — the strings `"connect failed"` and `"exit code 42"` come from the probe binary's panic-format output at `crates/nono-cli/src/bin/windows-net-probe.rs:36-37`.

**Root-cause hypotheses, ranked:**

1. **[HIGH-evidence] `--dangerous-force-wfp-ready` is gated by `#[cfg(debug_assertions)]` at `crates/nono-cli/src/cli.rs:1637-1640`.** In release-mode builds the flag does not exist in the CLI grammar. If `nono_bin()` resolves to a release-mode binary, clap rejects "unrecognized argument '--dangerous-force-wfp-ready'" before the probe ever spawns. The tracker's diagnostic "output is just the `nono v0.X.Y` banner" matches clap's standard "unknown argument" error which often prints version + help. **Validation:** check the GitHub Actions Windows workflow's cargo build invocation for the `nono` binary the test uses — if `--release` is set, this hypothesis is confirmed without needing to reproduce locally. The `set_windows_wfp_test_force_ready` runtime helper at `exec_strategy_windows/mod.rs:397-402` also `cfg(debug_assertions)`-gates its setter, so even if the flag parsed, the runtime path wouldn't activate without debug_assertions.

2. **[MEDIUM-evidence] Probe binary not built or not on `CARGO_BIN_EXE_windows-net-probe`'s resolution path.** `windows_net_probe_bin()` at `env_vars.rs:41-43` reads `env!("CARGO_BIN_EXE_windows-net-probe")` — set at compile time by Cargo for the test crate when `crates/nono-cli/src/bin/windows-net-probe.rs` is a known bin target. If `bin` target metadata is mis-declared in `crates/nono-cli/Cargo.toml`, the env var would be unset → compile failure (so this case wouldn't compile, ruling it out). The probe binary IS at `crates/nono-cli/src/bin/windows-net-probe.rs` (verified). Less likely than (1).

3. **[LOW-evidence] WFP filter setup fails before probe spawns.** If `windows_wfp_test_force_ready()` returns false (which it does in release builds per hypothesis 1) AND no real WFP service is registered, the test path may emit a "not ready" diagnostic and skip the probe. The test's third assertion `!text.contains("install-wfp-service")` explicitly checks against THIS shape — if it triggered, the third assertion would fail, not the second. So this case is partially excluded by the assertions ordering. But if hypothesis 1 holds, the third assertion also wouldn't reach evaluation because the first assertion (`!output.status.success()`) would have failed (release mode + unrecognized flag = clap returns non-zero, so the first assertion passes, but the second fails).

**Recommended planner task:**

- **Task 1 (1h):** Read `.github/workflows/ci.yml` Windows job(s) to confirm whether the `nono` binary built for these integration tests has `debug_assertions` set. If CI uses `cargo test --workspace` (no `--release`), `debug_assertions` is on by default and hypothesis 1 fails. If CI uses `cargo test --release`, hypothesis 1 is confirmed.
- **Task 2 (decision pivot):** 
  - If hypothesis 1 confirmed → either promote `--dangerous-force-wfp-ready` out of `cfg(debug_assertions)` (small product surface change — needs `#[arg(long, hide = true)]` to stay hidden in user-facing `--help`), OR change the test build profile.
  - If hypothesis 1 rejected → reproduce locally on Windows host with `cargo test -p nono-cli --test env_vars windows_run_block_net_blocks_probe_connection -- --nocapture` and capture the actual stderr → narrow to hypothesis 2 vs 3.
- **Task 3:** Fix per the resolved hypothesis. Pattern (1a): promote flag (preferred — minimum churn). Pattern (1b): split the test fixture into a "release-safe" path that doesn't use the flag.

**Do NOT** add `#[ignore]` to these tests as a "fix". REQ-CI-02 SC#3 forbids `[ignored]` markers without an issue link.

### Plan 41-05 — env_vars parallel flake (`windows_run_redirects_profile_state_vars_into_writable_allowlist`)

**Test body (verified):** `crates/nono-cli/tests/env_vars.rs:1027-1078` runs `nono run --allow <dir> --workdir <workspace> -- cmd /c set` and asserts the captured `cmd /c set` output contains `path=c:\windows\system32;...`, `pathext=.com;.exe;.bat;.cmd`, `comspec=c:\windows\system32\cmd.exe`, `systemroot=c:\windows`, `windir=c:\windows`.

**The flake mechanism (per tracker):** "passes serially, fails on parallel runs." This is a textbook env-var contamination between parallel cargo tests in the same process. Rust test runner runs `#[test]` functions in parallel within the same process by default. Tests that read or modify process-global env vars race with each other.

**Candidate root causes:**

1. **Parallel test reads `nono_bin()`'s output text that shadows another test's `cmd /c set` output.** Unlikely — each test spawns a fresh subprocess and reads its own captured stdout.
2. **The test's environment expectations (PATH, PATHEXT, COMSPEC, SystemRoot, windir) are mutated by another concurrent test.** When `nono` resolves the runtime baseline, it reads process env, and a parallel test setting/clearing one of these vars before `nono` spawns the child would race.

**Recommended planner task:**

- **Task 1:** Grep for any test that mutates `PATH`, `PATHEXT`, `COMSPEC`, `SystemRoot`, `windir` (and case variations). Likely candidate: any test using `EnvVarGuard::set_all` with these keys.
- **Task 2 (preferred fix):** Wrap this test in `EnvVarGuard::set_all(&[("PATH", "<canonical>"), ("PATHEXT", "<canonical>"), ...])` so the test pins its OWN expected baseline before invoking `nono_bin()`. Drop-time restore preserves the original on test exit.
- **Task 2-alt:** Use `nono-cli/src/test_env.rs::lock_env()` (the existing process-global Mutex at line 12) to serialize env-mutating tests. This is what the comment at `test_env.rs:1-8` describes as the intended pattern. Less granular than per-test `EnvVarGuard` but works.
- **Task 3:** Verify the fix by running `cargo test -p nono-cli --test env_vars -- --test-threads=4` (default parallel) repeatedly (e.g., 10x) — flake reproduces on no run.

### Plan 41-06 — broker hygiene CR-01 + CR-02 + CR-03

**Three FFI/broker-argv changes per CONTEXT D-09 + D-10 + D-11 + D-12.**

#### CR-01 — FFI mapping

**Verified surfaces:**

- `bindings/c/src/lib.rs:132-138` carries the "Phase 31 D-07" doc-comment block:
  ```rust
  // Phase 31 D-07: BrokerNotFound is a path-resolution failure (the
  // broker.exe sibling lookup against std::env::current_exe() parent
  // returned a path that does not exist on disk). Map to
  // ErrPathNotFound for FFI consumers — same semantic class as
  // PathNotFound, just specifically named for the broker discovery
  // call site.
  nono::NonoError::BrokerNotFound { .. } => NonoErrorCode::ErrPathNotFound,
  ```
- `bindings/c/src/types.rs:168` defines `ErrSandboxInit = -6` (verified).
- `bindings/c/src/lib.rs:131` already maps `LabelApplyFailed { .. }` to `ErrSandboxInit` (precedent: this is the right semantic bucket for sandbox-init failures).

**Change shape (per CONTEXT D-09):**

1. Replace line 138's right-hand side: `=> NonoErrorCode::ErrPathNotFound,` → `=> NonoErrorCode::ErrSandboxInit,`.
2. Rewrite the 6-line doc-comment block (lines 132-137) to reflect the remap. Suggested rewrite:
   ```rust
   // Phase 41 D-09 (CR-01): BrokerNotFound is an installation/runtime
   // defect — the broker.exe sibling is missing from disk where
   // current_exe().parent() expected it. This is structurally a sandbox-
   // init failure (the supervisor cannot stand up its enforcement
   // primitive), NOT a user-input path-resolution failure. Map to
   // ErrSandboxInit alongside LabelApplyFailed.
   ```
3. Update `bindings/c/include/nono.h` doc-comment via cbindgen build (the .h is auto-generated; re-run the cbindgen build script to regenerate).

#### CR-02 — Null-handle reject

**Verified surface:** `crates/nono-shell-broker/src/main.rs:87-99` handles `--inherit-handle` parsing:
```rust
"--inherit-handle" => {
    let v = iter.next().ok_or_else(|| {
        NonoError::SandboxInit("--inherit-handle requires a hex value".into())
    })?;
    let hex_str = v.to_string_lossy();
    let stripped = hex_str.trim_start_matches("0x").trim_start_matches("0X");
    let raw_value = usize::from_str_radix(stripped, 16).map_err(|e| {
        NonoError::SandboxInit(format!(
            "--inherit-handle parse error for '{hex_str}': {e}"
        ))
    })?;
    inherit_handles.push(raw_value as HANDLE);
}
```

**Change shape:** After line 97 (`raw_value` is bound) and before line 98 (`inherit_handles.push(...)`):
```rust
if raw_value == 0 || raw_value == usize::MAX {
    return Err(NonoError::SandboxInit(format!(
        "--inherit-handle value '{hex_str}' is null or INVALID_HANDLE_VALUE; reject"
    )));
}
```

`INVALID_HANDLE_VALUE` is `(HANDLE)-1` which is `usize::MAX` on the pointer width. On 64-bit Windows, `0xFFFFFFFFFFFFFFFF`. Both checks are required for defense-in-depth per the CR-02 todo.

**Test (per D-11):** Add a `#[test] fn parse_args_null_inherit_handle_returns_error` in the existing test mod (around line 489) that argv-feeds `--inherit-handle 0x0` and asserts the returned error is `SandboxInit` with a message containing "null or INVALID_HANDLE_VALUE".

#### CR-03 — Empty handle list reject (per D-12)

**Verified surface:** The existing test at `crates/nono-shell-broker/src/main.rs:489-502` is:
```rust
/// D-02: an empty inherit-handle list is the most-restrictive (and
/// expected) shape — it means the spawned child inherits NO handles.
/// Construction MUST succeed with `inherit_handles.is_empty()`.
#[test]
fn parse_args_empty_inherit_handle_list_is_ok() {
    let raw = argv(&["--shell", "foo", "--cwd", r"C:\"]);
    let parsed = parse_args(&raw).expect("parse must succeed with no --inherit-handle");
    assert!(parsed.inherit_handles.is_empty(), ...);
    ...
}
```

**Change shape:**

1. **Add a post-parse reject** in `parse_args`. After line 122 (`Ok(BrokerArgs { ... })`), but before returning, insert:
   ```rust
   if inherit_handles.is_empty() {
       return Err(NonoError::SandboxInit(
           "--inherit-handle list is empty; broker requires at least one inheritable handle".into()
       ));
   }
   ```
   (Exact placement: after `let cwd = cwd.ok_or_else(...)?;` at line 116, before the `Ok(BrokerArgs { ... })`.)

2. **Flip the existing test** at line 489-502:
   - Rename: `parse_args_empty_inherit_handle_list_is_ok` → `parse_args_empty_inherit_handle_list_returns_error`.
   - Replace assert: `let Err(NonoError::SandboxInit(msg)) = parse_args(&raw) else { panic!("expected SandboxInit error on empty --inherit-handle list"); }; assert!(msg.contains("empty"), ...);`.
   - Update the doc-comment: change "MUST succeed" → "MUST fail" with rationale referencing Phase 41 D-12.

3. **Note the broker's runtime `args.inherit_handles.clone()` site** at `crates/nono-shell-broker/src/main.rs:200` is now structurally unreachable for `is_empty()` — the parser blocks. Consider also adding `debug_assert!(!args.inherit_handles.is_empty(), ...)` at line 200 as a defense-in-depth sanity check. (Discretionary.)

4. **Update Plan 31-02 SUMMARY's "empty list = most-restrictive" claim** — per CONTEXT this becomes "correct-by-construction-rejected" in Phase 41. Locate the claim in `.planning/phases/31-broker-process-architecture-shell-01/31-02-SUMMARY.md` (path inferred from .archive shape) and append an "Update (Phase 41)" subsection.

#### Manual verification check (per D-10)

In Plan 41-06 task list, add a verification step: read `../nono-py/` and `../nono-ts/` repo sources (working directories assumed accessible per CLAUDE.md project layout). Search for any code that maps FFI error code `-1` (the old `ErrPathNotFound`) to a Python `FileNotFoundError` or TypeScript `PathNotFoundError` distinct from sandbox-init. If found, file a follow-up todo in `.planning/todos/pending/`. If not found (both repos `match nono.last_error_string()` or treat all negative codes as opaque), no further action.

### Plan 41-07 — broker CR-04 + baseline reset close gate

**Two technical changes + three docs commits per CONTEXT D-13 + D-14 + D-16.**

#### CR-04 — Test SKIP → FAIL (per D-13)

**Verified surface:** `crates/nono-cli/src/exec_strategy_windows/launch.rs:2450-2460`:
```rust
let broker_path = if candidate_triple.exists() {
    candidate_triple
} else if candidate_default.exists() {
    candidate_default
} else {
    eprintln!(
        "SKIP: broker artifact missing at {} and {} — pre-build via \
         `cargo build -p nono-shell-broker --release --target x86_64-pc-windows-msvc` \
         to exercise D-04 Job Object containment locally. ...",
        candidate_triple.display(),
        candidate_default.display()
    );
    return;
};
```

**Change shape:** Replace the `eprintln!` + `return;` arm with:
```rust
} else {
    panic!(
        "nono-shell-broker.exe missing at {} and {}; pre-build with \
         `cargo build -p nono-shell-broker --release` (or set the broker pre-build \
         via crates/nono-cli/build.rs per Phase 41 D-14). This test asserts \
         Job Object containment is enforced before ResumeThread and cannot be \
         silently skipped — see CR-04 disposition.",
        candidate_triple.display(),
        candidate_default.display()
    );
};
```

The `panic!` value-of-expression makes the `if/else if/else` arms type-check (the `else` arm has type `!` which coerces to `PathBuf`).

#### Broker pre-build via build.rs (per D-14)

**Verified surface:** `crates/nono-cli/build.rs` exists (86 lines). Lines 70-84 already have a `if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")` block staging the placeholder WFP driver.

**Change shape:** Add a sibling block (or extend the existing windows block) that invokes `cargo build -p nono-shell-broker --release` when target is Windows. Approach options:

- **Option A: cargo subprocess from build.rs.** Use `std::process::Command::new("cargo").args(["build", "-p", "nono-shell-broker", "--release"]).status()`. Risk: build.rs running cargo recursively can cause lock contention with the parent cargo invocation. Mitigation: use `cargo build` with `--target-dir` pointing at a separate dir, or skip if `CARGO` env var indicates we're already inside a recursive build.
- **Option B: `[dev-dependencies]` declaration.** Declare `nono-shell-broker` as a dev-dependency of `nono-cli`; cargo will build it before running tests. Cleaner; this is the idiomatic Rust pattern for "tests need this other binary built".
- **Option C: cargo's `links =` build-script declaration + cargo metadata.** More involved; overkill here.

**Option B is cleanest** but the planner verifies that adding `nono-shell-broker` as a path dev-dep doesn't introduce a workspace cycle (verify: nono-shell-broker should not depend on nono-cli either directly or transitively). **CONTEXT § Claude's Discretion permits planner choice.**

#### Baseline reset (per D-16)

**Three commits:**

##### 1. `docs(41): reset baseline-aware CI gate to Phase 41 close SHA`

**Critical finding:** `.planning/templates/upstream-sync-quick.md` does NOT currently contain a baseline SHA. The file uses `{from_tag}..{to_tag}` placeholders (upstream tags, lines 22, 25, 27, 32, 34, 49, 101, 113) for the upstream-sync workflow. The CONTEXT D-16 wording "updates `.planning/templates/upstream-sync-quick.md` baseline SHA" likely means **add** a baseline SHA section (or repurpose an existing section), not find-and-replace.

The actual `a72736bb` baseline reference lives in:
- `.planning/STATE.md` (Phase 40 Wave 1 commentary)
- `.planning/PHASE-41-TRACKER.md`
- `.planning/REQUIREMENTS.md` § CI-CLEAN context paragraph
- `.planning/ROADMAP.md` § Phase 41 success criteria

**Recommended commit shape:**

Add a new section to `upstream-sync-quick.md` titled `## Baseline-aware CI gate` (placement: after `## Drift inventory`, before `## Conflict-file inventory`). The section reads:

```markdown
## Baseline-aware CI gate

For upstream-sync waves landing on top of a known-green baseline, the close
gate flags ONLY `success → failure` transitions vs the baseline. Drift
accumulates across milestones; reset at each milestone-internal cleanup.

**Current baseline SHA:** `<Phase 41 close SHA — set after Phase 41 ships>`
**Last reset:** Phase 41 close (REQ-CI-03), 2026-05-15 → cleaning the
pre-existing red carried forward from baseline `a72736bb`.
**Reset cadence:** Every milestone-internal cleanup phase (see Phase 41 for
the v2.5 precedent).

CI gate result interpretation:
- Lane was green on baseline AND is green on PR head: PASS.
- Lane was green on baseline AND is red on PR head: FAIL (real regression).
- Lane was red on baseline AND is red on PR head: PASS (carry-forward, not
  introduced by this PR).
- Lane was red on baseline AND is green on PR head: PASS + IMPROVEMENT.
```

The literal SHA stays as `<Phase 41 close SHA — set after Phase 41 ships>` because the actual SHA is unknown until Phase 41 merges. The Plan 41-07 final task can either:
- Land this commit with the placeholder and follow up post-merge to fill the SHA, OR
- Land as the very last commit in the PR (after CR-04 + build.rs commits) using the PR head SHA at the moment of close.

##### 2. `docs(41): document skipped_gates_load_bearing vs _environmental convention`

Add a SUMMARY frontmatter convention block at the top of Phase 41's eventual SUMMARY.md (will be created by `/gsd-complete-phase`). The block content describes:

- **`skipped_gates_load_bearing`**: gates that MUST pass and were skipped due to a load-bearing reason (e.g., cross-target clippy gates 3+4 skipped because Windows-host lacks C cross-compilers for `aws-lc-sys`/`ring`; the GAP is real and CI compensates by running native Linux + macOS clippy lanes).
- **`skipped_gates_environmental`**: gates that don't apply to this run (e.g., a macOS-only test skipped on a Linux runner; not load-bearing).

This is process documentation; the planner copies the wording from `.planning/STATE.md`'s D-40-C2 entries which already use this language.

##### 3. `docs(41): clear v24 CR-A deferred items from STATE.md`

**Verified surface:** `.planning/STATE.md:218-233` (`### v2.4 close — acknowledged 2026-05-15` table) contains:
- Row `todo × 4 | v24-cr-0[1-4]-* | pending | v24 code-review todos ...` — REMOVE (CR-01..04 are resolved by Plans 41-06 + 41-07).
- The `Known deferred items at v2.4 close: ... + 4 v24 CR todos + ...` summary line at line 233 — UPDATE to remove the `+ 4 v24 CR todos` segment and decrement the total.

Other rows (requirements, uat_gap, verification_gap, context_question, quick_task) remain — they're not v24-CR-A class.

**Planner task list shape:**

- Task 1: CR-04 SKIP → FAIL change at `launch.rs:2450-2460`.
- Task 2: `build.rs` broker pre-build extension at `crates/nono-cli/build.rs` (Option A or B per planner).
- Task 3: cargo test -p nono-cli to verify the broker is built automatically + the test exercises the panic path on missing artifact (via deliberate `target/<triple>/release/` cleanup as part of the test infra).
- Task 4: Commit baseline reset block addition to `upstream-sync-quick.md`.
- Task 5: Commit `skipped_gates_*` convention frontmatter block.
- Task 6: Commit STATE.md `## Deferred Items` cleanup.
- Task 7 (close gate per D-15): verify all 7 CI lanes green on PR head; zero `success → failure` transitions vs `a72736bb`.

## Verification Standard (copy verbatim into every Plan touching Unix code)

```
# Cross-target clippy invariant (memory feedback_clippy_cross_target).
# Required from the Windows host on every Linux-touching commit. Windows-host
# workspace clippy CANNOT see #[cfg(target_os = "linux")] or
# #[cfg(target_os = "macos")] blocks; an unused-import inside such a block is
# invisible to the local lint pass.

cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used

# Darwin target verification:
# If the local cross-toolchain is available, also run:
cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used
# Otherwise, the macOS CI runner provides the verification. The Windows
# dev host typically lacks C cross-compilers for aws-lc-sys/ring; gates 3+4
# of the standard D-40-C2 checklist are documented-skipped → CI-verified.

# Reference: Phase 25 CR-A regression lesson (2026-04-XX); Phase 40 Wave 0
# CR-A regression at commit 4665ae75 (latent unused-import in sandbox/mod.rs
# that workspace clippy missed because consumers were all inside Windows-
# only cfg blocks).
```

## Runtime State Inventory

**Not a rename/refactor/migration phase.** Phase 41 is mechanical lint cleanup + targeted code-hygiene fixes; no string-replacement scope, no datastore key migrations, no OS-registered name changes. This section is omitted per the GSD researcher template's "include for rename/refactor/migration phases only" guidance.

## Common Pitfalls

### Pitfall 1: Adding `#[allow(dead_code)]` to silence Plan 41-02 warnings

**What goes wrong:** Reviewer/CI accepts the change; lint passes; orphan stays in codebase as dead weight.
**Why it happens:** Fastest local fix; tempting when investigation is slow.
**How to avoid:** Forbidden by CLAUDE.md "lazy use of dead code" + REQ-CI-01 SC#4. Either delete (`audit_ledger.rs` mass-delete) or cfg-gate (per-function `#[cfg(target_os = "windows")]` for items with Windows-only callers).
**Warning signs:** Any task labeled "silence the warning" instead of "investigate the orphan".

### Pitfall 2: Bulk-applying Plan 41-01 migration without spike

**What goes wrong:** A type mismatch surfaces at site 11/14 (e.g., a `&PathBuf` vs `&Path` deref discrepancy at one site), and the planner has to back out 10 sites of churn.
**Why it happens:** "It's just a field rename" mentality.
**How to avoid:** Spike at site 2662 (first occurrence). Run cross-target clippy. Verify the pattern compiles AND lints clean. Bulk-apply only after the spike succeeds.
**Warning signs:** Any task list that lists 14 site edits without a SPIKE task in front.

### Pitfall 3: Adding `#[ignore]` to Plan 41-04 tests as a "fix"

**What goes wrong:** REQ-CI-02 SC#3 forbids `[ignored]` markers without issue link; verifier catches in the close gate.
**Why it happens:** Root cause TBD pre-spike; quick path appeals.
**How to avoid:** Per CONTEXT D-04 + REQ-CI-02 SC#3, Plan 41-04 root cause must be resolved. If the planner identifies a genuine deferral (e.g., requires WFP service install), file an explicit issue link + `#[ignore = "<reason>; tracked in #NNN"]`.
**Warning signs:** Task list shows "mark test as ignored" without an issue number.

### Pitfall 4: Updating `.planning/templates/upstream-sync-quick.md` baseline SHA via find-replace

**What goes wrong:** The template does NOT currently contain a baseline SHA; find-replace finds nothing; planner thinks the task is "no-op" and skips it.
**Why it happens:** CONTEXT D-16 wording suggests an existing line update; reality is an additive section.
**How to avoid:** Plan 41-07 baseline-reset task explicitly says "ADD section `## Baseline-aware CI gate` after `## Drift inventory`" per the Plan 41-07 brief above. The template change is structural, not textual.
**Warning signs:** Task description that says "update SHA value" without specifying location/section name.

### Pitfall 5: CR-01 doc-comment rewrite forgetting `bindings/c/include/nono.h`

**What goes wrong:** `bindings/c/src/lib.rs` doc-comment block updated; `nono.h` still carries the old text; downstream FFI consumers (nono-py docs) inherit the stale rationale.
**Why it happens:** `nono.h` is auto-generated by cbindgen; easy to forget the regeneration step.
**How to avoid:** Plan 41-06 task list includes "regenerate `nono.h` via cbindgen" as an explicit task. Verify via `git diff bindings/c/include/nono.h` shows the doc-comment update.
**Warning signs:** Task list ends at "edit lib.rs" without a header regeneration step.

### Pitfall 6: build.rs recursive cargo invocation (Plan 41-07 Option A)

**What goes wrong:** `cargo build` from inside build.rs deadlocks on the cargo file lock when run during `cargo test` of the parent crate.
**Why it happens:** Cargo holds a process-global lock; nested invocations from build.rs collide.
**How to avoid:** Prefer Option B (`[dev-dependencies]` declaration) over Option A. If Option A is chosen, point the nested invocation at a separate `--target-dir` to sidestep the lock.
**Warning signs:** Task description says "build.rs invokes cargo" without `--target-dir` flag.

## Code Examples

Verified patterns from the existing codebase:

### Pattern: cfg-gated allow(dead_code) for cross-platform struct fields

Source: `crates/nono-cli/src/exec_strategy.rs:380-381` (verified)
```rust
/// Whether direct LaunchServices opening is enabled for this session.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub allow_launch_services_active: bool,
```

This is the precedent for Plan 41-02's `audit_recorder` field (line 376) if the disposition is "cfg-gate" rather than "delete". Apply `#[cfg_attr(not(target_os = "windows"), allow(dead_code))]`.

### Pattern: per-impl-block disallowed_methods allow with rationale

Source: `crates/nono-cli/src/test_env.rs:24` and `:56` (verified)
```rust
#[allow(clippy::disallowed_methods)] // This IS the safe wrapper around env var mutation.
impl EnvVarGuard {
    ...
}

#[allow(clippy::disallowed_methods)] // Restoring env vars is the other half of the safe wrapper.
impl Drop for EnvVarGuard {
    ...
}
```

This is the CONTEXT D-08 pattern. Apply identically to `profile_runtime.rs`'s `EnvGuard` impl (or replace `EnvGuard` with `EnvVarGuard` import).

### Pattern: HandleTarget consumer (for Plan 41-01 reference)

Source: `crates/nono/src/supervisor/aipc_sdk.rs:99` (verified)
```rust
let target = HandleTarget::SocketEndpoint {
    protocol,
    host,
    port,
    role,
};
```

The SDK side BUILDS `HandleTarget` variants; the supervisor side (`exec_strategy.rs`) READS them via `match`. Plan 41-01's helper pattern (see **Pattern 1** above) is the read side.

### Pattern: SandboxInit error shape in broker argv parser

Source: `crates/nono-shell-broker/src/main.rs:88-97` (verified)
```rust
let v = iter.next().ok_or_else(|| {
    NonoError::SandboxInit("--inherit-handle requires a hex value".into())
})?;
```

CR-02 + CR-03 reject patterns mirror this shape. Use `NonoError::SandboxInit(format!(...))` consistently — same error class, structured message.

## State of the Art

This is fork-internal cleanup; "state of the art" is the codebase's own evolving conventions:

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `CapabilityRequest::path` direct read | `target: Option<HandleTarget>` with deprecated-`path` fallback | Phase 18 (AIPC-01), v2.0 era | Plan 41-01 finishes the migration on supervisor read side |
| `std::env::set_var/remove_var` in test helpers | `crate::test_env::EnvVarGuard` Drop-restore primitive | Phase 19 era; lint added later | Plan 41-02 brings final stragglers into the abstraction |
| `NonoError::BrokerNotFound → ErrPathNotFound` (Phase 31 D-07 mapping) | `NonoError::BrokerNotFound → ErrSandboxInit` (Phase 41 D-09) | THIS PHASE | Semantically correct; no ABI surface change |
| Silent SKIP on missing broker artifact (Plan 31-05 design) | `panic!` + build.rs pre-build (Phase 41 D-13 + D-14) | THIS PHASE | CI signal-quality improvement; no false PASS |
| `## Deferred Items` accumulates carry-forward | Reset at each milestone-internal cleanup phase | Phase 41 establishes precedent | Plan 41-07 D-16 reset shape |

**Deprecated/outdated:**

- `CapabilityRequest::path: PathBuf` field — marked `#[deprecated]` since Phase 18; Plan 41-01 migrates reads; actual struct-field removal deferred to a future phase (see comment at `crates/nono/src/supervisor/types.rs:159-162`).
- `eprintln!` SKIP path in `broker_launch_assigns_child_to_job_object` — removed by Plan 41-07.
- Plan 31-02 SUMMARY's "empty `--inherit-handle` list = most-restrictive" claim — superseded by Plan 41-06 CR-03 disposition (c) reject.

## Assumptions Log

This research project followed the verify-before-asserting discipline. All claims above are tagged implicitly as `[VERIFIED: source file:line]` via the precise file:line references. The following items deserve explicit assumption flags:

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The `_disallowed_methods_` Clippy errors on Linux originate from `profile_runtime.rs:331,343,344` (NOT `test_env.rs:343,344` per the stale tracker). | Plan 41-02 § Site Correction | Low — Plan 41-02 spike will reveal exact origins via `cargo clippy --message-format=json` |
| A2 | The block-net probe test failure traces to `cfg(debug_assertions)`-gated `--dangerous-force-wfp-ready`. | Plan 41-04 hypothesis 1 (HIGH-evidence) | Medium — fall-back is hypothesis 2 + 3 investigation; impact is task ordering inside Plan 41-04 |
| A3 | The 17 `audit_ledger.rs` symbols have zero non-test callers across the workspace. | Plan 41-02 dead-code inventory | Low — verified via `grep -r 'audit_ledger::' crates/`. Risk: a future commit added a caller after our grep snapshot. Spike re-verifies before delete-commit. |
| A4 | `nono-shell-broker` does not depend on `nono-cli`. | Plan 41-07 Option B | Low — the broker is a Medium-IL helper binary, structurally separate. If it did depend, Option A or C are fallbacks. |
| A5 | `.planning/templates/upstream-sync-quick.md` does not already contain a baseline SHA section (the template uses upstream tags, not fork-side baseline SHAs). | Plan 41-07 Pitfall 4 | None — verified by full file read 2026-05-15. |

## Open Questions

1. **`exec_identity::NotApplicable` and `pty_proxy::shutdown_attach_listener` dispositions.**
   - What we know: PHASE-41-TRACKER lists them as dead-code orphans; grep showed no obvious external callers.
   - What's unclear: whether they're Windows-only callsites visible only via cfg-gate, or true orphans.
   - Recommendation: planner runs `cargo clippy --workspace --target x86_64-unknown-linux-gnu --message-format=json 2>&1 | jq '.message.spans[]?.file_name' | sort -u` during spike to enumerate exact warning origins; classify each per CONTEXT D-05 tree.

2. **Cbindgen regeneration trigger for `bindings/c/include/nono.h`.**
   - What we know: `nono.h` is auto-generated.
   - What's unclear: whether the Phase 41 PR build regenerates it automatically (e.g., via build.rs) or requires a manual `cargo build -p nono-ffi` step.
   - Recommendation: Plan 41-06 first task verifies the regeneration pipeline; if manual, the planner adds a task to regenerate post-doc-comment edit and commits the regenerated header.

3. **Plan 41-04 hypothesis 1 confirmation needs CI workflow read.**
   - What we know: `--dangerous-force-wfp-ready` is `cfg(debug_assertions)`-gated.
   - What's unclear: whether GitHub Actions Windows Security job builds with `--release` (kills the flag) or default (keeps it).
   - Recommendation: Plan 41-04 task 1 reads `.github/workflows/ci.yml` for the relevant Windows test invocation; this is a 5-minute lookup, not a research-pass deep-dive.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust 1.77+ | All Phase 41 work | ✓ (per CLAUDE.md) | 1.77 | — |
| Cargo | All Phase 41 work | ✓ | bundled | — |
| `x86_64-unknown-linux-gnu` rustup target | Cross-target clippy verification | ? (planner verifies via `rustup target list --installed`) | — | Fork CI Linux Clippy lane provides equivalent coverage |
| C cross-compiler for Linux target | Cross-target clippy compile of `aws-lc-sys`/`ring` | ✗ (per Phase 40 D-40-C2 documented skip) | — | CI runner provides; gate 3+4 documented-skipped per `skipped_gates_load_bearing` convention |
| PowerShell 5.1+ | Plan 41-03 MSI validator edit | ✓ (Windows host) | — | — |
| `nono-shell-broker.exe` artifact | Plan 41-07 CR-04 test runs locally | ✗ (until Plan 41-07 build.rs lands) | — | Plan 41-07 makes it automatic; transitively required for D-13 panic to be exercised locally |
| `gh` CLI | Memory `feedback_gh_available` — PR creation per D-15 | ✓ | — | — |

**Missing dependencies with no fallback:** None.

**Missing dependencies with fallback:** C cross-compiler for Linux clippy — CI compensates per Phase 40 precedent.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in test runner (`cargo test`) + `proptest` (`crates/nono-cli/`) |
| Config file | `Cargo.toml` per-crate; workspace `Cargo.toml` at root |
| Quick run command | `cargo test -p nono-cli --lib` (unit tests, fast) |
| Full suite command | `cargo test --workspace --all-targets` (all integration + unit + doc tests) |
| Clippy gate | `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` (cross-platform AND cross-target per D-06) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| REQ-CI-01 | Linux/macOS Clippy lints resolved | clippy (workspace + cross-target) | `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` | ✅ (toolchain exists) |
| REQ-CI-02 | Windows CI jobs green | integration (GitHub Actions) | `gh run list --workflow=ci.yml --branch=<PR-head>` + verify all 5 Windows jobs `success` | ✅ (workflow exists) |
| REQ-CI-03 | Baseline-aware gate reset | docs verification | `git diff .planning/templates/upstream-sync-quick.md` shows new baseline section | ✅ (template exists) |
| REQ-BROKER-CR-01 | FFI BrokerNotFound → ErrSandboxInit | unit | `cargo test -p nono-ffi error_code_for_broker_not_found_is_sandbox_init` | ❌ Wave 0 — new test per CONTEXT D-11 |
| REQ-BROKER-CR-02 | Broker null-handle reject | unit | `cargo test -p nono-shell-broker parse_args_null_inherit_handle_returns_error` | ❌ Wave 0 — new test per CONTEXT D-11 |
| REQ-BROKER-CR-03 | Broker empty-list reject | unit | `cargo test -p nono-shell-broker parse_args_empty_inherit_handle_list_returns_error` | ❌ Wave 0 — existing test FLIPS per CONTEXT D-12 |
| REQ-BROKER-CR-04 | Job-object test FAILS on missing artifact | integration | `cargo test -p nono-cli --test broker_launch_assigns_child_to_job_object` (run on Windows with broker artifact deliberately absent — should panic) | ✅ (test exists at `launch.rs:2423`; D-13 changes its behavior) |

### Sampling Rate

- **Per task commit:** `cargo test -p <touched-crate> --lib` + `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` from Windows host.
- **Per wave merge:** Full clippy cross-target sweep (`cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings`) + full `cargo test --workspace --all-targets`.
- **Phase gate (per D-15):** Draft PR CI lane sweep on PR head — all 7 lanes green + zero `success → failure` transitions vs baseline `a72736bb`. Run by `/gsd-verify-phase 41`.

### Wave 0 Gaps

Three new tests need to exist before Plan 41-06 ships:

- [ ] `crates/nono-ffi/<test-file>` or `crates/nono/tests/<test-file>` — REQ-BROKER-CR-01 FFI mapping assert (`NonoError::BrokerNotFound` → `NonoErrorCode::ErrSandboxInit (-6)`). The planner picks the location based on where the existing `nono_error_to_error_code` function's test coverage lives.
- [ ] `crates/nono-shell-broker/src/main.rs` test module — REQ-BROKER-CR-02 null-handle reject test (add ~line 488, near existing argv tests).
- [ ] `crates/nono-shell-broker/src/main.rs` test module — REQ-BROKER-CR-03 empty-list reject test (FLIP existing test at line 493 per CONTEXT D-12).

Framework install: none — `cargo test` and `cargo clippy` already work in this workspace.

## Security Domain

Phase 41 is hygiene cleanup, not a new-feature phase. Security implications:

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | — (no auth surface touched) |
| V3 Session Management | no | — |
| V4 Access Control | no | — |
| V5 Input Validation | **yes** | Broker argv parser hardening (CR-02 null-handle, CR-03 empty-list) is input validation at the broker boundary |
| V6 Cryptography | no | — |

### Known Threat Patterns for Phase 41

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Pseudo-handle confusion via `--inherit-handle 0x0` (Win32 `(HANDLE)0` can resolve to caller's pseudo-handle in some paths) | Elevation of Privilege (EoP) | CR-02 reject null at argv parser; structured error before `UpdateProcThreadAttribute` |
| `ERROR_BAD_LENGTH` undefined behavior on empty `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` | Tampering / Denial of Service | CR-03 reject empty list at argv parser; broker parser becomes consistent enforcement boundary |
| Semantically incorrect FFI error code masks real failure class (false `FileNotFoundError` for installation defect) | Information Disclosure (misdirection) | CR-01 remap `BrokerNotFound → ErrSandboxInit` |
| False-PASS class on missing broker artifact (CR-04) | Failure of CI security signal | D-13 SKIP → FAIL + D-14 build.rs pre-build |
| Cross-target lint blind spot (Phase 25 CR-A regression class) | Bypass of static analysis | D-06 cross-target clippy invariant enforced on every Linux-touching commit |

**Defense-in-depth note:** CONTEXT § Verifier note observes CR-03's production path is structurally unreachable in `nono-cli` (always emits both `pty_pair.input_write` and `pty_pair.output_read` per `exec_strategy_windows/launch.rs:1379-1382`). CR-03's argv-parser reject hardens against direct broker misuse (e.g., a future caller, a test harness, or an attacker with broker-spawn primitives) — defense-in-depth against the secondary attack surface, even though the primary surface is sealed.

## Sources

### Primary (HIGH confidence)

- `crates/nono/src/supervisor/types.rs:95-196` — `HandleTarget` enum + `CapabilityRequest` struct definition (verified read 2026-05-15)
- `crates/nono-cli/src/exec_strategy.rs:370-389` — `SupervisorRunArgs<'a>` struct (audit_recorder field at line 376; allow_launch_services_active precedent at line 380)
- `crates/nono-cli/src/exec_strategy.rs:2650-2820` — 14 API migration sites (sampled read 2026-05-15)
- `crates/nono-cli/src/exec_strategy.rs:1920-1947` — unreachable expression at line 1930 (verified)
- `crates/nono-cli/src/test_env.rs` (67 lines total) — full read 2026-05-15
- `crates/nono-cli/src/profile_runtime.rs:320-347` — `EnvGuard` Drop impl, candidates for D-08 fence migration
- `crates/nono-cli/src/audit_ledger.rs:1-80` — orphan inventory verified
- `crates/nono-cli/src/audit_integrity.rs:217` — `record_capability_decision` definition + `exec_strategy_windows/supervisor.rs:1832` caller
- `crates/nono-cli/src/exec_strategy_windows/launch.rs:2420-2460` — `broker_launch_assigns_child_to_job_object` SKIP path
- `crates/nono-cli/src/exec_strategy_windows/mod.rs:396-413` — `set_windows_wfp_test_force_ready` cfg gating
- `crates/nono-cli/src/cli.rs:1637-1640` — `dangerous_force_wfp_ready` flag cfg gating
- `crates/nono-cli/src/bin/windows-net-probe.rs` (40 lines total) — probe binary source
- `crates/nono-cli/tests/env_vars.rs:773-825`, `:914-968`, `:1028-1078` — block-net probe + parallel flake test bodies
- `crates/nono-shell-broker/src/main.rs:75-150` — argv parser; lines 87-99 are `--inherit-handle` handling
- `crates/nono-shell-broker/src/main.rs:489-502` — existing empty-list test (FLIPS per D-12)
- `bindings/c/src/lib.rs:120-145` — `nono_error_to_error_code` mapping; CR-01 fix site at line 138
- `bindings/c/src/types.rs:130-186` — `NonoErrorCode` enum (target `ErrSandboxInit = -6` at line 168)
- `scripts/validate-windows-msi-contract.ps1` (full file read 2026-05-15) — missing `BrokerPath` thread-through
- `scripts/build-windows-msi.ps1:1-25` — `BrokerPath` mandatory declaration
- `crates/nono-cli/build.rs` (86 lines total) — full read; lines 70-84 are existing Windows block, extension point for D-14
- `clippy.toml` (5 lines total) — `disallowed-methods` config full
- `.planning/templates/upstream-sync-quick.md` (full file read) — verified NO baseline SHA section exists
- `.planning/STATE.md:185-233` — `## Deferred Items` + `### v2.4 close — acknowledged 2026-05-15` table
- `.planning/PHASE-41-TRACKER.md` (full file read 2026-05-15)
- `.planning/phases/41-ci-cleanup-v24-broker-code-review-closure/41-CONTEXT.md` (full file read 2026-05-15)
- `.planning/REQUIREMENTS.md` (full file read 2026-05-15)
- `.planning/ROADMAP.md` (full file read 2026-05-15)
- `.planning/todos/pending/v24-cr-0[1-4]-*.md` (all four full reads 2026-05-15)
- `CLAUDE.md` (project instructions, full read)

### Secondary (MEDIUM confidence)

- Memory `feedback_clippy_cross_target` — Phase 25 CR-A regression lesson; cited verbatim in cross-target clippy invariant section
- Memory `project_workspace_crates` — workspace has 5 crates, cited in CLAUDE.md enforcement section
- Memory `feedback_gh_available` — `gh` CLI is available; cited in Environment Availability
- Memory `project_cross_fork_pr_pattern` — fork umbrella PR pattern (D-15 references)

### Tertiary (LOW confidence)

None — every claim in this research is sourced from verified file:line evidence or explicitly tagged as ASSUMED in the Assumptions Log above.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — no new deps; entire stack is in existing CLAUDE.md
- Architecture (sub-plan briefs): HIGH — every file:line reference verified via direct source read 2026-05-15
- Pitfalls: HIGH — sourced from CONTEXT decisions + STATE.md Phase 40 D-40-C2 precedent + Phase 25 CR-A regression lesson
- Dead-code dispositions: MEDIUM — `audit_ledger.rs` mass-delete confidence is HIGH (grep verified); a handful of TBDs (`exec_identity::NotApplicable`, `pty_proxy::shutdown_attach_listener`) need spike-time `cargo clippy --message-format=json` enumeration. Recorded in Open Questions.
- Plan 41-04 root cause: MEDIUM — hypothesis 1 is HIGH-evidence but unconfirmed without `.github/workflows/ci.yml` read or local Windows test reproduction; documented in Open Questions.

**Research date:** 2026-05-15
**Valid until:** 2026-05-22 (7 days; source code reads have a short shelf life — any merge to `main` between research and execution may invalidate file:line references)

---

*Phase 41 — CI cleanup + v24 broker code-review closure*
*Research complete. Ready for `/gsd-plan-phase 41`.*
