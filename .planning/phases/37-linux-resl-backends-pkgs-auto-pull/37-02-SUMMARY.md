---
phase: 37-linux-resl-backends-pkgs-auto-pull
plan: 02
subsystem: cli-flag, profile-resolver
tags: [cli-flag, env-var, profile-resolver, auto-pull, no-auto-pull]
dependency_graph:
  requires:
    - phase-26-02 (load_registry_profile auto-pull plumbing; is_registry_ref discriminator)
  provides:
    - "ProfileResolverArgs struct (cli.rs:1476) flattened into RunArgs (cli.rs:2117) + WrapArgs (cli.rs:2319)"
    - "ResolveContext struct (profile/mod.rs:2178)"
    - "load_profile_with_context (profile/mod.rs:2211) + load_registry_profile_with_context (profile/mod.rs:2269)"
    - "diagnostic_formatter::format_error_footer (new module)"
    - "prepare_sandbox_with_context (sandbox_prepare.rs:217) + prepare_profile_with_context (profile_runtime.rs)"
  affects:
    - "Plan 37-05 e2e integration test consumes --no-auto-pull suppression branch"
tech_stack:
  added:
    - "clap BoolishValueParser + num_args(0..=1) + default_missing_value pattern for env-var-driven bool flag"
  patterns:
    - "Pattern 3: wrapper-with-default for context-param threading (CONTEXT.md / PATTERNS.md)"
    - "Pattern B: EnvVarGuard + lock_env for env-var tests (CLAUDE.md mandate)"
key_files:
  created:
    - "crates/nono-cli/src/diagnostic_formatter.rs (new module; format_error_footer helper)"
  modified:
    - "crates/nono-cli/src/cli.rs (ProfileResolverArgs struct + 2 flatten sites + 6 unit tests)"
    - "crates/nono-cli/src/profile/mod.rs (ResolveContext + load_profile_with_context wrapper + load_registry_profile_with_context with D-11 suppression branch + 4 unit tests)"
    - "crates/nono-cli/src/profile_runtime.rs (prepare_profile_with_context; legacy prepare_profile removed)"
    - "crates/nono-cli/src/sandbox_prepare.rs (prepare_sandbox_with_context body + thin prepare_sandbox wrapper)"
    - "crates/nono-cli/src/command_runtime.rs (run_sandbox dry-run + run_wrap both paths thread ResolveContext)"
    - "crates/nono-cli/src/launch_runtime.rs (prepare_run_launch_plan threads ResolveContext)"
    - "crates/nono-cli/src/main.rs (register diagnostic_formatter mod)"
    - ".github/scripts/check-cli-doc-flags.sh (awk extractor extended to walk ProfileResolverArgs)"
    - "docs/cli/usage/flags.mdx (new --no-auto-pull entry + env-var table row)"
decisions:
  - "D-09 honored: scope is `nono run` + `nono wrap` only; `nono pull` rejects --no-auto-pull at clap-parse time"
  - "D-10 honored: NONO_NO_AUTO_PULL env var counterpart with CLI > env precedence (clap default behavior under BoolishValueParser)"
  - "D-11 honored: suppression branch returns NonoError::ProfileNotFound verbatim with the package-ref string preserved"
  - "D-12 honored: ResolveContext is a struct parameter; zero thread-locals / globals introduced"
  - "Pattern 3 (wrapper-with-default) applied at three layers: load_profile, prepare_profile, prepare_sandbox"
metrics:
  duration: "approx 35 minutes wall-clock executor time"
  completed: 2026-05-19
  tests_added: 13
  tests_passing: 13/13 (Task1 6 + Task2 ResolveContext 4 + diagnostic_footer 3)
  files_modified: 9
  files_created: 1
---

# Phase 37 Plan 37-02: Auto-Pull Suppression Flag (`--no-auto-pull`) Summary

One-liner: New `--no-auto-pull` CLI flag + `NONO_NO_AUTO_PULL` env var, scoped to `nono run` / `nono wrap` per D-09, threaded through a new `ResolveContext` parameter (D-12) and a `DiagnosticFormatter`-style footer hint (D-11) when the suppression branch fires.

## Objective Met

Closes REQ-PKGS-04 acceptance #4 ("`--no-auto-pull` flag (new) skips auto-pull and falls back to the legacy 'profile not found' error"). Establishes the `ResolveContext` extension point so Plan 37-05's e2e integration test (which verifies the suppression path) lands without further plumbing changes.

## What Was Built

### Task 1 — `ProfileResolverArgs` + flatten into `RunArgs`/`WrapArgs`

- New struct: `crates/nono-cli/src/cli.rs:1476` (`pub struct ProfileResolverArgs { pub no_auto_pull: bool }`).
- Flatten sites:
  - `RunArgs` at `crates/nono-cli/src/cli.rs:2117`
  - `WrapArgs` at `crates/nono-cli/src/cli.rs:2319`
- `PullArgs` (cli.rs:1100) and `ShellArgs` (cli.rs:2265) NOT flattened per D-09.
- New `help_heading = "PROFILE"` introduced; CI doc-flag script (`.github/scripts/check-cli-doc-flags.sh`) extended to walk `ProfileResolverArgs`.
- `docs/cli/usage/flags.mdx` gains a `--no-auto-pull` entry under the Profile Options section and an env-var table row.

### Task 2 — `ResolveContext` threading + D-11 suppression branch + diagnostic footer

- `ResolveContext` struct: `crates/nono-cli/src/profile/mod.rs:2178`.
- `load_profile_with_context`: `crates/nono-cli/src/profile/mod.rs:2211` — wrapper-with-default. Existing `load_profile(name)` (line ~2200) is now a thin shim over the `_with_context` variant.
- `load_registry_profile_with_context`: `crates/nono-cli/src/profile/mod.rs:2269` — contains the D-11 suppression branch (`if ctx.no_auto_pull { return Err(NonoError::ProfileNotFound(...)) }`). The branch emits the diagnostic footer to stderr BEFORE returning the error so the user sees the suppression cause inline.
- `crates/nono-cli/src/diagnostic_formatter.rs` (new): `format_error_footer(&NonoError, &ResolveContext) -> Option<String>`.
- `crates/nono-cli/src/profile_runtime.rs`: `prepare_profile_with_context(args, silent, workdir, ctx)`. The legacy `prepare_profile` was removed (its only caller, `sandbox_prepare::prepare_sandbox`, switched to the new variant).
- `crates/nono-cli/src/sandbox_prepare.rs:217`: `prepare_sandbox_with_context(args, silent, ctx)`. Existing `prepare_sandbox` (line 214) is now a thin wrapper that supplies `&ResolveContext::default()` for sites outside the run/wrap handlers (notably `nono shell` at command_runtime.rs:93/105, which is correctly out of D-09 scope).

### Call sites updated to `_with_context` (D-09 in-scope handlers only)

| File | Function | Line |
|------|----------|------|
| `crates/nono-cli/src/command_runtime.rs` | `run_sandbox` (RunArgs dry-run) | 47 |
| `crates/nono-cli/src/command_runtime.rs` | `run_wrap` (WrapArgs dry-run) | 176 |
| `crates/nono-cli/src/command_runtime.rs` | `run_wrap` (WrapArgs main path) | 189 |
| `crates/nono-cli/src/launch_runtime.rs` | `prepare_run_launch_plan` (RunArgs main path) | 260 |

Other `prepare_sandbox(args, silent)` call sites (`run_shell` at command_runtime.rs:93 and 105) remain on the legacy entry point and inherit pre-Phase-37 behavior (auto-pull enabled). `nono shell` is out of D-09 scope by design.

## DiagnosticFormatter footer text (VERBATIM, for downstream UAT reference)

```
Hint: --no-auto-pull is set; auto-pull suppressed. Re-run without the flag or unset NONO_NO_AUTO_PULL to fetch the profile.
```

Contains the substring `--no-auto-pull` (acceptance grep gate) and the word `set` (Test 5 assertion).

## Confirmations

- `PullArgs` NOT modified (D-09 scope honored). Verified by smoke test: `nono pull --no-auto-pull namespace/foo` errors with `unexpected argument '--no-auto-pull' found`.
- `ShellArgs` NOT modified (D-09 scope honored). Verified by reading the struct definition; `nono shell` continues to use the legacy `prepare_sandbox` entry point and inherits pre-Phase-37 auto-pull behavior.
- ZERO `thread_local!` / `static .* AtomicBool` introduced (D-12 anti-pattern guard). Verified by Grep gate on `profile/mod.rs` (returns no matches).
- Diagnostic footer fires ONLY on `(ProfileNotFound, ctx.no_auto_pull == true)` (Test 5 + 2 silent-case tests guard against false positives).

## clap Env-Var Bool-Parsing Quirk (Note for Plan 37-05)

The initial implementation used `action = clap::ArgAction::SetTrue` mirroring the `--block-net` precedent at cli.rs:1555. This caused `NONO_NO_AUTO_PULL=1` to NOT populate the field (test `profile_resolver_args_env_var_sets_true` failed). Root cause: clap's `SetTrue` action does not consume the env-var VALUE — it only sets the field when the flag is *present*, and env vars don't trigger "flag present" without `num_args`.

Fix landed: switched to `num_args = 0..=1 + default_missing_value = "true" + default_value_t = false + BoolishValueParser`. This makes the flag take an *optional* boolean value, so:
- bare `--no-auto-pull` → `true` (via `default_missing_value`)
- `--no-auto-pull true` / `--no-auto-pull yes` / `--no-auto-pull 1` → `true`
- `--no-auto-pull false` / `--no-auto-pull no` / `--no-auto-pull 0` → `false`
- `NONO_NO_AUTO_PULL=1` env var (no CLI flag) → `true`
- `NONO_NO_AUTO_PULL=0` env var + `--no-auto-pull` CLI → `true` (CLI wins per D-10)
- No flag + no env → `false` (via `default_value_t`)

This pattern is the modern clap-4 idiom for env-var-driven boolean flags and was preferred over modifying the existing `--block-net` shape. The existing `--block-net` / `--allow-net` flags retain the `SetTrue` shape (verified to NOT have unit-test coverage for env-var-only activation, so any latent quirk there is out of scope for Plan 37-02).

## Verification

| Check | Result |
|-------|--------|
| `cargo test -p nono-cli --bin nono profile_resolver_args_tests` | 6/6 green |
| `cargo test -p nono-cli --bin nono resolve_context_tests` | 4/4 green |
| `cargo test -p nono-cli --bin nono diagnostic_footer_tests` | 3/3 green |
| `cargo test -p nono-cli --bin nono profile::` | 224/224 green (no regressions) |
| `cargo test -p nono-cli --bin nono cli::` | 102/102 green (no regressions) |
| `cargo build -p nono-cli` | clean |
| `cargo clippy -p nono-cli --bin nono --tests -- -D warnings -D clippy::unwrap_used` | clean on host (Windows) |
| Cross-target Linux clippy (`--target x86_64-unknown-linux-gnu`) | **PARTIAL** — host lacks `x86_64-linux-gnu-gcc` cross-toolchain for native C deps (`aws-lc-sys`). Deferred to live CI per `.planning/templates/cross-target-verify-checklist.md`. Plan 37-02 introduces NO new `#[cfg(target_os = ...)]` branches and touches NO files under `exec_strategy/` or `bindings/c/src/`, so cross-target gate is structurally less load-bearing here than for Plan 37-01 (error variant) or 37-03 (cfg-gated formatter). |
| Cross-target macOS clippy (`--target x86_64-apple-darwin`) | **PARTIAL** — host lacks `cc` for cross-compile. Same disposition as Linux. |
| Smoke test: `nono run --help` shows `--no-auto-pull` under PROFILE heading | PASS |
| Smoke test: `nono wrap --help` shows `--no-auto-pull` under PROFILE heading | PASS |
| Smoke test: `nono pull --no-auto-pull namespace/foo` is rejected by clap | PASS (`unexpected argument`) |

## Acceptance-Criteria Grep Gates

| Gate | Expected | Actual |
|------|----------|--------|
| `pub struct ProfileResolverArgs` in cli.rs | 1 | 1 (line 1476) |
| `env = "NONO_NO_AUTO_PULL"` in cli.rs | 1 | 1 |
| `help_heading = "PROFILE"` in cli.rs | 1 | 1 |
| `pub profile_resolver: ProfileResolverArgs` in cli.rs | 2 | 2 (lines 2117 + 2319) |
| `ProfileResolverArgs` inside PullArgs region | 0 | 0 (verified by clap parse-rejection smoke test) |
| `pub struct ResolveContext` in profile/mod.rs | 1 | 1 (line 2178) |
| `pub fn load_profile_with_context` in profile/mod.rs | 1 | 1 (line 2211) |
| `fn load_registry_profile_with_context` in profile/mod.rs | 1 | 1 (line 2269) |
| `if ctx.no_auto_pull` in profile/mod.rs | 1 | 1 (line 2279) |
| `load_profile_with_context(` call sites under nono-cli/src | ≥ 2 | 6 (1 wrapper + 5 internal uses) |
| `thread_local!|static.*AtomicBool` in profile/mod.rs | 0 | 0 (D-12 anti-pattern guard satisfied) |
| `no-auto-pull` in diagnostic_formatter.rs | ≥ 1 | 10 (struct doc + helper + 3 tests) |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocker] clap env-var bool-parsing quirk**

- **Found during:** Task 1 GREEN
- **Issue:** Initial `ProfileResolverArgs` declaration mirrored the existing `--block-net` shape (`action = SetTrue` + `BoolishValueParser`). Test `profile_resolver_args_env_var_sets_true` failed because clap's `SetTrue` action doesn't read env-var VALUES.
- **Fix:** Switched to `num_args(0..=1) + default_missing_value("true") + default_value_t(false) + BoolishValueParser`. Documented in this SUMMARY (see "clap Env-Var Bool-Parsing Quirk" section above) for downstream awareness.
- **Files modified:** `crates/nono-cli/src/cli.rs` (struct definition)
- **Commit:** `d3a4c1b2`

**2. [Rule 2 - Missing critical functionality] dry-run path didn't honor --no-auto-pull**

- **Found during:** Task 2 GREEN, when threading ResolveContext into call sites.
- **Issue:** `command_runtime::run_sandbox` has a `dry_run` branch that called `prepare_sandbox(&args, silent)` directly. Without threading the ResolveContext, a user running `nono run --no-auto-pull --dry-run --profile namespace/foo -- cmd` would have had auto-pull fire during dry-run preview — defeating the audit/airgap workflow this flag was designed for.
- **Fix:** Captured `resolve_ctx` at function entry (before `run_args.sandbox.clone()` moves the field) and threaded it into both the dry-run and the main `prepare_run_launch_plan` paths. Same fix applied to `run_wrap`'s dry-run branch.
- **Files modified:** `crates/nono-cli/src/command_runtime.rs`
- **Commit:** `26ba8282`

**3. [Rule 1 - Bug] Doc comment leaking clap implementation rationale into --help output**

- **Found during:** Final smoke test (`nono run --help`).
- **Issue:** The `ProfileResolverArgs.no_auto_pull` field had a multi-paragraph `///` doc comment that described both the user-facing flag semantics AND the internal Phase 37 D-10 + clap value-parser rationale. clap-4 renders ALL `///` lines into `--help`, so users saw a noisy 4-line implementation lecture under each occurrence of `--no-auto-pull`.
- **Fix:** Split the comment — kept the user-facing 3-line summary as `///` (clap renders it), demoted the Phase 37 D-10 rationale to a plain `//` code comment above the `#[arg(...)]` attribute (clap ignores it).
- **Files modified:** `crates/nono-cli/src/cli.rs`
- **Commit:** `1deec893`

### Out-of-Scope Discoveries (deferred-items.md)

- **`--dangerous-force-wfp-ready` CI doc-flag drift**: Pre-existing Phase 41 test-only flag never added to `docs/cli/usage/flags.mdx`. Logged in `deferred-items.md`.
- **`broker_launch_assigns_child_to_job_object` test failure on host**: Pre-existing Phase 41 D-14 release-mode broker pre-build requirement (test expects `target/release/nono-shell-broker.exe`). Logged in `deferred-items.md`. Plan 37-02 does NOT touch `exec_strategy_windows/launch.rs` or the broker harness.

## Authentication Gates

None encountered. All work was offline (no registry / network access required).

## Known Stubs

None. The `--no-auto-pull` flag and `ResolveContext` are fully wired end-to-end on the D-09 in-scope handlers. The legacy `prepare_sandbox` wrapper (for `nono shell` and other out-of-scope sites) intentionally supplies a default `ResolveContext`, which IS the design (preserves pre-Phase-37 behavior for non-run/non-wrap commands).

## Commits

| Hash | Type | Message |
|------|------|---------|
| `77fef183` | test | Task 1 RED: 6 failing tests for ProfileResolverArgs |
| `d3a4c1b2` | feat | Task 1 GREEN: ProfileResolverArgs + flatten + CI doc-script + flags.mdx |
| `89fb418f` | test | Task 2 RED: 4 ResolveContext tests + 3 diagnostic_formatter tests |
| `26ba8282` | feat | Task 2 GREEN: ResolveContext + load_profile_with_context + suppression + call-site wiring |
| `1deec893` | style | Trim ProfileResolverArgs doc comment for clean clap --help output |

## TDD Gate Compliance

Plan 37-02 has `type: execute` (not `type: tdd`), but BOTH tasks were marked `tdd="true"` and followed the gate sequence per task:

- **Task 1**: `test(37-02): ...` (77fef183, RED) → `feat(37-02): ...` (d3a4c1b2, GREEN). No refactor gate needed.
- **Task 2**: `test(37-02): ...` (89fb418f, RED) → `feat(37-02): ...` (26ba8282, GREEN). One follow-up `style(37-02): ...` commit (1deec893) is a UX polish, not a semantic refactor.

Both tasks had a clean RED→GREEN cycle. The RED gate was confirmed via `cargo test --no-run` (compile-fail on missing types) before the GREEN implementation.

## Self-Check: PASSED

Files verified to exist (all 12 reported in `key_files` and `created`):

| Path | Status |
|------|--------|
| `crates/nono-cli/src/diagnostic_formatter.rs` | FOUND |
| `crates/nono-cli/src/cli.rs` | FOUND |
| `crates/nono-cli/src/profile/mod.rs` | FOUND |
| `crates/nono-cli/src/profile_runtime.rs` | FOUND |
| `crates/nono-cli/src/sandbox_prepare.rs` | FOUND |
| `crates/nono-cli/src/command_runtime.rs` | FOUND |
| `crates/nono-cli/src/launch_runtime.rs` | FOUND |
| `crates/nono-cli/src/main.rs` | FOUND |
| `.github/scripts/check-cli-doc-flags.sh` | FOUND |
| `docs/cli/usage/flags.mdx` | FOUND |
| `.planning/phases/37-linux-resl-backends-pkgs-auto-pull/deferred-items.md` | FOUND |
| `.planning/phases/37-linux-resl-backends-pkgs-auto-pull/37-02-SUMMARY.md` | FOUND |

Commits verified to exist on branch:

| Hash | Status |
|------|--------|
| `77fef183` (Task 1 RED) | FOUND |
| `d3a4c1b2` (Task 1 GREEN) | FOUND |
| `89fb418f` (Task 2 RED) | FOUND |
| `26ba8282` (Task 2 GREEN) | FOUND |
| `1deec893` (style polish) | FOUND |

No deletions across any of the 5 commits (verified via `git diff --diff-filter=D --name-only HEAD~N HEAD` per commit).

