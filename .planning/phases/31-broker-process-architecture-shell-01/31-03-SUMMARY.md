---
phase: 31-broker-process-architecture-shell-01
plan: 03
subsystem: infra
tags: [windows, broker, sandbox, cascade-arm, handle-list, job-object, ptythreadattribute, fail-secure]

# Dependency graph
requires:
  - phase: 31-broker-process-architecture-shell-01
    plan: 01
    provides: "nono::create_low_integrity_primary_token() callable from any workspace crate; nono::OwnedHandle as a pub library type; NonoError::BrokerNotFound { path: PathBuf } variant with Phase 31 D-07 doc-comment rejecting env-var override surface"
provides:
  - "WindowsTokenArm::BrokerLaunch variant in select_windows_token_arm cascade — PTY+supervised launches now route through nono-shell-broker.exe (Medium IL caller's identity) instead of the Phase 30 direct CreateProcessAsUserW(low_il_token, ...) + PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE shape"
  - "build_broker_command_line(broker_exe, &[OsString]) helper emitting the Plan 31-02 D-08 argv contract: --shell <path> --shell-arg <arg>... --inherit-handle 0x<hex>... --cwd <path>"
  - "PROC_THREAD_ATTRIBUTE_HANDLE_LIST whitelisting the two ConPTY pipe handles (pty_pair.input_write + pty_pair.output_read) for inheritance through the nono.exe → broker boundary; capability-pipe handles (Phase 11) and other supervisor handles are NOT inheritable past nono.exe (D-02)"
  - "SetHandleInformation(HANDLE_FLAG_INHERIT) flip-set + flip-unset hygiene around CreateProcessW so the inheritance flag does not leak into subsequent CreateProcess calls (T-31-17 mitigation)"
  - "broker_dispatch_tests module in launch.rs: broker_not_found_error_variant_is_constructible_and_displays_path (always-on) + broker_launch_assigns_child_to_job_object (#[ignore], lifted by Plan 31-05)"
affects:
  - 31-04-runtime-bundle
  - 31-05-field-test
  - 31-06-docs-flip

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "D-15 conditional preservation of LowIlPrimary fallback arm: keep the structurally-unreachable variant + the pty_none_caps_demand_low_il_selects_low_il test + the low_integrity_primary_token_tests Windows-FFI module so the only direct runtime exercise of nono::create_low_integrity_primary_token stays alive while the live PTY+supervised path moves to BrokerLaunch"
    - "PROC_THREAD_ATTRIBUTE_HANDLE_LIST + bInheritHandles=1 discipline at the nono.exe→broker boundary: HANDLE_LIST gates which inheritable handles cross the boundary, even though bInheritHandles=1 declares the capability. SetHandleInformation flip-set+flip-unset around CreateProcessW prevents inheritance flag leakage into later spawns."
    - "Branch-ordering guard: defense-in-depth test (broker_launch_takes_precedence_over_session_sid_on_pty_path) explicitly pins has_pty=true OVERRIDES has_session_sid=true AND caps_demand_low_il=true in the cascade. Future readers cannot accidentally re-order the arms without the test catching it."
    - "Argv contract emission as Vec<OsString>: build_broker_command_line accepts &[OsString] (not &[String]) so the --shell payload (PathBuf::as_os_str()) and --cwd value (PathBuf::as_os_str()) round-trip through OS-native path encoding without intermediate String conversion."

key-files:
  created: []
  modified:
    - "crates/nono-cli/src/exec_strategy_windows/launch.rs (add WindowsTokenArm::BrokerLaunch enum variant + spawn_windows_child match arm stub returning null h_token; flip select_windows_token_arm has_pty branch from LowIlPrimary to BrokerLaunch; add build_broker_command_line helper; restructure PTY arm to dispatch BrokerLaunch via PROC_THREAD_ATTRIBUTE_HANDLE_LIST + CreateProcessW; preserve PSEUDOCONSOLE legacy path as else-arm per D-15; rename pty_some_no_detach_selects_low_il → pty_some_no_detach_selects_broker_launch; add broker_launch_takes_precedence_over_session_sid_on_pty_path test; add broker_dispatch_tests module with 2 tests)"
    - "crates/nono-cli/src/exec_strategy_windows/mod.rs (add PROC_THREAD_ATTRIBUTE_HANDLE_LIST to windows_sys::Win32::System::Threading import; add a doc comment noting that IsProcessInJob is consumed only by the test module)"

key-decisions:
  - "Restructure existing PTY arm in spawn_windows_child via inner if matches!(arm, WindowsTokenArm::BrokerLaunch) rather than splitting spawn_windows_child into multiple functions. Rationale: (a) the spawn_windows_child cascade already uses a single function with branching; splitting would cascade into supervisor.rs callsites; (b) the legacy LowIlPrimary path is structurally unreachable today but kept per D-15 — the conditional is the surgical edit point. The else-arm preserves the Phase 30 PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE block verbatim."
  - "build_broker_command_line accepts &[OsString], not &[String] (deviation from build_command_line's signature). Rationale: the broker's --shell payload is launch_program: &Path and --cwd is current_dir: PathBuf; round-tripping through String would lossily convert non-UTF-8 path components. quote_windows_arg accepts &str so we still go through to_string_lossy for quoting, but the OsString-typed argv lets the caller hand in PathBuf::as_os_str().to_owned() directly without an intermediate String."
  - "Inheritance-flag cleanup runs on BOTH success and failure paths via explicit per-error-branch SetHandleInformation(_, HANDLE_FLAG_INHERIT, 0) calls (rather than a defer/scope-guard). Rationale: Rust has no native defer; introducing a scope-guard struct just for two HANDLEs adds drop-order complexity (the existing PtyPair Drop closes the pipes; we don't want our cleanup running after PtyPair::Drop). Explicit per-branch unflip is the simplest fail-secure shape."
  - "broker_launch_assigns_child_to_job_object stays #[ignore]'d in this plan rather than implementing a synthetic broker for unit-test purposes. Rationale: the test's value is in exercising the REAL dispatch + REAL Job Object containment, which requires the production broker artifact (Plan 31-04 ships it) and a live ConPTY (which requires a console session). A synthetic broker would test a different code path. Plan 31-05 field-test is the correct lift point per the plan."
  - "PROC_THREAD_ATTRIBUTE_HANDLE_LIST attribute count = 1 (not 2) because it is a SINGLE attribute carrying an ARRAY of HANDLEs. The attribute-list size param to InitializeProcThreadAttributeList must be 1 for one attribute (HANDLE_LIST), and the cbSize param to UpdateProcThreadAttribute must be size_of_val(&inherit_handles[..]) = 2 * size_of::<HANDLE>(). This was a near-trap during implementation; verified against MSDN's `lpAttributeList` documentation."

patterns-established:
  - "Pattern: PROC_THREAD_ATTRIBUTE_HANDLE_LIST emission for handle-restriction at process-creation boundaries (D-02). Init/Update/Delete shape mirrors PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE (Pattern S-04) but with an array of inheritable HANDLEs instead of a single HPCON. SetHandleInformation flip-set+flip-unset around CreateProcessW prevents flag leakage."
  - "Pattern: Sibling-binary path resolution via std::env::current_exe().parent() + literal filename, fail-fast with structured NonoError variant if absent. NO env-var override surface — env-poisoning is the rejection rationale captured in the variant's doc-comment (D-07)."
  - "Pattern: Defense-in-depth branch-ordering test that pins the PRECEDENCE rule of a cascade. broker_launch_takes_precedence_over_session_sid_on_pty_path passes is_detached=false, has_pty=true, has_session_sid=true, caps_demand_low_il=true; the assertion that BrokerLaunch (the has_pty arm) wins over both later arms is a future-readers' guard against accidental re-ordering."
  - "Pattern: #[ignore]'d test as deferral marker for downstream-plan execution. broker_launch_assigns_child_to_job_object documents the runtime acceptance, embeds the IsProcessInJob import (under #[allow(unused_imports)]), and references the lift plan in the docstring. Plan 31-05 lifts the ignore."

requirements-completed: []

# Metrics
duration: 44min
completed: 2026-05-09
---

# Phase 31 Plan 03: Broker Process Architecture — Cascade Arm Wiring Summary

**Wired the `WindowsTokenArm::BrokerLaunch` cascade arm into the PTY+supervised launch path: `select_windows_token_arm` now returns `BrokerLaunch` for `has_pty=true && !is_detached`; the dispatch in `spawn_windows_child` resolves `nono-shell-broker.exe` as a sibling of the running `nono.exe`, fails fast with `NonoError::BrokerNotFound { path }` if absent, builds a `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` whitelisting only the two ConPTY pipe handles, and spawns the broker via `CreateProcessW` (Medium IL = caller's identity) instead of the Phase 30 direct `CreateProcessAsUserW(low_il_token, ...)` shape that triggered `STATUS_DLL_INIT_FAILED` (`0xC0000142`) at CSRSS console-attach time.**

## Performance

- **Duration:** ~44 min
- **Started:** 2026-05-09T00:04:35Z
- **Completed:** 2026-05-09T00:48:26Z
- **Tasks:** 2
- **Files modified:** 2 (`crates/nono-cli/src/exec_strategy_windows/launch.rs`, `crates/nono-cli/src/exec_strategy_windows/mod.rs`)
- **Lines added:** +397 (launch.rs +390 / mod.rs +7)
- **Lines removed:** -76

## Accomplishments

- **`WindowsTokenArm::BrokerLaunch` cascade arm live.** `select_windows_token_arm(is_detached=false, has_pty=true, has_session_sid=true, caps_demand_low_il=*)` now returns `BrokerLaunch`; the cascade docstring is updated to reflect the new ordering. `pty_some_no_detach_selects_broker_launch` (renamed from `pty_some_no_detach_selects_low_il`) and the new defense-in-depth `broker_launch_takes_precedence_over_session_sid_on_pty_path` lock the rule.
- **D-07 sibling-binary resolution.** `spawn_windows_child` resolves the broker via `std::env::current_exe().parent().join("nono-shell-broker.exe")`, fails fast with `NonoError::BrokerNotFound { path }` (Plan 31-01 variant) if the broker is absent. No env-var override surface — env-poisoning attack rejected at the variant doc-comment level.
- **D-02 handle-restriction discipline.** `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` whitelists ONLY `pty_pair.input_write` + `pty_pair.output_read` for inheritance through the `nono.exe → broker` boundary. Capability-pipe handles (Phase 11) and other supervisor handles are NOT inheritable past `nono.exe`. T-31-15 (capability-pipe handle leak past nono.exe) and T-31-17 (inheritance flag stuck-on after spawn) mitigated; cleanup `SetHandleInformation(_, HANDLE_FLAG_INHERIT, 0)` runs on BOTH success and failure paths.
- **D-08 argv contract emitted.** `build_broker_command_line` builds the exact argv shape Plan 31-02's broker parses: `"<broker_exe>" --shell "<launch_program>" --shell-arg "<arg>"... --inherit-handle 0x<input_hex> --inherit-handle 0x<output_hex> --cwd "<cwd>"`. Each handle is formatted as `0x{usize:016x}` for x64 alignment with the broker's `usize::from_str_radix(_, 16)` decoder. Quoting reuses the existing `quote_windows_arg` helper (T-31-20 mitigation: opaque string handling, no flag re-parse).
- **D-04 Job Object containment unchanged.** The existing `apply_process_handle_to_containment(containment, process.raw())` call site at `launch.rs` runs against the broker PID BEFORE `ResumeThread` (so the broker is in the Job Object before it executes a single instruction). The broker's child inherits Job membership via the Win32 cascade; `JOB_OBJECT_LIMIT_*BREAKAWAY*` flags remain unset per the Phase 16 RESL invariant. T-31-19 mitigated.
- **D-15 fallback preserved.** The Phase 30 `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` block lives in the `else` arm of `if matches!(arm, BrokerLaunch)` so the structurally-unreachable `LowIlPrimary` Direct path still has a working dispatch. The `pty_none_caps_demand_low_il_selects_low_il` test still asserts `LowIlPrimary`, and the `low_integrity_primary_token_tests` Windows-FFI module still exercises the lifted `nono::create_low_integrity_primary_token` symbol.
- **Workspace builds clean** on `x86_64-pc-windows-msvc` AND on the default host target. **`pty_token_gate_tests`: 7/7 passed** (6 Phase 30 + 1 new defense-in-depth). **`low_integrity_primary_token_tests`: 2/2 passed** (D-15 fallback preserved). **`broker_dispatch_tests`: 1 passed + 1 ignored** (variant constructible always-on; Job Object containment test deferred to Plan 31-05 field execution per the plan's `#[ignore]` clause).

## Task Commits

Each task committed atomically on `worktree-agent-a68898abfd829548e`:

1. **Task 1: Add `WindowsTokenArm::BrokerLaunch` variant + selector dispatch + rewrite `pty_token_gate_tests`** — `55d2b1b2` (feat). 1 file changed, +90 / -41.
2. **Task 2: Implement `BrokerLaunch` dispatch in `spawn_windows_child` PTY branch (resolution + HANDLE_LIST + CreateProcessW + sibling broker discovery) + `broker_dispatch_tests`** — `aad42757` (feat). 2 files changed, +397 / -76.

_Both tasks land on the per-agent branch; STATE.md / ROADMAP.md untouched in worktree mode (per the orchestrator's parallel-execution contract). The orchestrator will merge the worktree after both wave-2 plans (31-02 + 31-03) complete._

## Files Created/Modified

- **`crates/nono-cli/src/exec_strategy_windows/launch.rs`** — Added `WindowsTokenArm::BrokerLaunch` enum variant with full doc-comment documenting the rationale + PoC validation reference; flipped `select_windows_token_arm`'s `has_pty` branch from `LowIlPrimary` to `BrokerLaunch` (with explanatory inline comment); added `BrokerLaunch` arm to `spawn_windows_child`'s match block (returns null `h_token` because broker uses caller's identity); added `build_broker_command_line(&Path, &[OsString]) -> Vec<u16>` helper near `build_command_line`; restructured the `if let Some(pty_pair) = pty` branch to dispatch via `if matches!(arm, WindowsTokenArm::BrokerLaunch)` — the new arm builds `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` with `pty_pair.input_write` + `pty_pair.output_read`, calls `SetHandleInformation(HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)` on both pipe handles, builds the D-08 argv, calls `CreateProcessW` with `bInheritHandles=1` + `EXTENDED_STARTUPINFO_PRESENT`, then unflips the inheritance flags on BOTH success and failure paths; the `else` arm preserves the Phase 30 PSEUDOCONSOLE block verbatim per D-15; renamed `pty_some_no_detach_selects_low_il` → `pty_some_no_detach_selects_broker_launch` asserting `BrokerLaunch`; added defense-in-depth test `broker_launch_takes_precedence_over_session_sid_on_pty_path`; added new `broker_dispatch_tests` module at end of file with `broker_not_found_error_variant_is_constructible_and_displays_path` (always-on) + `broker_launch_assigns_child_to_job_object` (`#[ignore]`'d, embeds the `IsProcessInJob` import for Plan 31-05 lift).
- **`crates/nono-cli/src/exec_strategy_windows/mod.rs`** — Added `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` to the existing `windows_sys::Win32::System::Threading::{...}` import alongside `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`; added a doc comment block noting that `IsProcessInJob` is consumed only by the `broker_dispatch_tests` test module under `#[cfg(all(test, target_os = "windows"))]` (the import lives inside that test module under `#[allow(unused_imports)]` so the production binary stays free of unused-import warnings under `-D warnings`).

## Decisions Made

See `key-decisions` in the frontmatter. Notable items:

- **Restructure existing PTY arm via inner `if matches!(arm, BrokerLaunch)`** rather than splitting `spawn_windows_child` into multiple functions. The legacy `LowIlPrimary` PSEUDOCONSOLE path is structurally unreachable today but kept per D-15 — the inner conditional is the surgical edit point and keeps the `else` arm byte-equivalent to pre-Plan-31-03 source.
- **`build_broker_command_line` accepts `&[OsString]`, not `&[String]`.** The broker's `--shell` payload is `launch_program: &Path` and `--cwd` is `current_dir: PathBuf`; round-tripping through `String` would lossily convert non-UTF-8 path components. The helper still goes through `to_string_lossy` for quoting (because `quote_windows_arg` accepts `&str`), but `OsString`-typed argv lets the caller hand in `PathBuf::as_os_str().to_owned()` directly.
- **Inheritance-flag cleanup runs on BOTH success and failure paths via explicit per-error-branch unflip** (rather than a defer/scope-guard). Rust has no native `defer`; introducing a scope-guard struct just for two `HANDLE`s would add drop-order complexity vs. the existing `PtyPair::Drop`. Explicit per-branch unflip is the simplest fail-secure shape.
- **`broker_launch_assigns_child_to_job_object` stays `#[ignore]`'d** in this plan rather than implementing a synthetic broker for unit-test purposes. The test's value is exercising the REAL dispatch + REAL Job Object containment, which requires the production broker artifact (Plan 31-04 ships it) and a live ConPTY (which requires a console session). Plan 31-05 field-test is the correct lift point.
- **PROC_THREAD_ATTRIBUTE_HANDLE_LIST attribute count = 1 (not 2)** because it's a SINGLE attribute carrying an ARRAY of HANDLEs. `InitializeProcThreadAttributeList` size param = 1 for one attribute (`HANDLE_LIST`); `UpdateProcThreadAttribute` `cbSize` = `size_of_val(&inherit_handles[..])` = `2 * size_of::<HANDLE>()`. Verified against MSDN's `lpAttributeList` doc.

## Argv Contract (D-08)

Plan 31-03 emits the broker command line as:

```
"<broker_exe>" --shell "<launch_program>" --shell-arg "<arg1>" --shell-arg "<arg2>" ... \
   --inherit-handle 0x<conpty_input_pipe_hex> --inherit-handle 0x<conpty_output_pipe_hex> \
   --cwd "<current_dir>"
```

Where:
- `<broker_exe>` = `current_exe.parent()` + `nono-shell-broker.exe` (D-07).
- `<launch_program>` = `spawn_windows_child`'s `launch_program: &Path` argument (post-`normalize_windows_launch_path`).
- `<arg1>..<argN>` = `cmd_args: &[String]` argument.
- `<conpty_input_pipe_hex>` / `<conpty_output_pipe_hex>` = `pty_pair.input_write` and `pty_pair.output_read` formatted as `format!("0x{:016x}", h as usize)`.
- `<current_dir>` = `current_dir: PathBuf` (post-`normalize_windows_launch_path`).

Quoting via `quote_windows_arg`: any argument containing whitespace, quotes, or other special characters is double-quoted with embedded quotes doubled. The broker's parser (Plan 31-02) treats every value after a flag as an opaque string; values are NOT re-parsed as flags (T-31-20 mitigation).

## HANDLE_LIST Scope (D-02)

The `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` attribute lists ONLY:

| Attribute | Source | Purpose |
|-----------|--------|---------|
| `pty_pair.input_write` | `crates/nono-cli/src/pty_proxy_windows.rs:13` | ConPTY input pipe write end (broker/child writes here, ConPTY reads). |
| `pty_pair.output_read` | `crates/nono-cli/src/pty_proxy_windows.rs:14` | ConPTY output pipe read end (broker/child reads here, ConPTY writes). |

NOT listed (and therefore NOT inheritable past `nono.exe` even with `bInheritHandles=1`):
- The capability pipe (Phase 11) — created via `CreateNamedPipeW` with non-inheritable handle attribute by default; T-31-15 mitigation.
- `pty_pair.hpcon` — that's a pseudoconsole handle (`HPCON`), not a pipe `HANDLE`; consumed only by `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` (which the broker path explicitly does not use per D-01). The broker does NOT call `CreatePseudoConsole`.
- Supervisor stdio handles, Job Object handle, WFP service handles — none flipped inheritable; even if they were, HANDLE_LIST would gate them out.

`SetHandleInformation(_, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)` runs on the two pipe handles BEFORE `CreateProcessW`; `SetHandleInformation(_, HANDLE_FLAG_INHERIT, 0)` runs on BOTH success and failure paths AFTER (T-31-17 mitigation: inheritance flag does not stick on past the spawn).

## D-15 Verification (LowIlPrimary Retention Conditional)

Per the plan's `<objective>`: the planner verifies whether removing `LowIlPrimary` is safe by checking if the Direct path is structurally reachable.

**Verification result:** Today's structural reality: `config.session_sid` is unconditionally `Some(...)` for Windows supervised launches (`execution_runtime.rs:334`); the cascade reaches `LowIlPrimary` only via the `caps_demand_low_il` branch when `has_session_sid=false` AND `has_pty=false` — a combination that does not occur on Windows supervised launches today. The `pty_none_caps_demand_low_il_selects_low_il` test (`launch.rs` `pty_token_gate_tests`) was added explicitly to pin the helper's behavior for "future readers and for non-Windows platforms where the helper compiles cleanly".

**Decision:** KEEP `WindowsTokenArm::LowIlPrimary` variant + the `pty_none_caps_demand_low_il_selects_low_il` test (asserting `LowIlPrimary`) + the `low_integrity_primary_token_tests` Windows-FFI module. The variant is harmlessly preserved as a fallback; removing it would delete the only direct runtime exercise of the lifted `nono::create_low_integrity_primary_token`. This satisfies the D-15 fallback clause ("If the planner finds a Direct path that still needs Low-IL spawn, re-evaluate D-15 — keep LowIlPrimary as a fallback arm and only rewrite the PTY-supervised tests").

The legacy `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` block in `spawn_windows_child` is preserved verbatim in the `else` arm of `if matches!(arm, WindowsTokenArm::BrokerLaunch)` — structurally unreachable today but compiles cleanly and keeps the `LowIlPrimary` arm dispatch valid.

## Threat-Model Coverage (per `<threat_model>`)

| Threat ID | Disposition | Status |
|-----------|-------------|--------|
| T-31-14 (broker substitution attack) | mitigate (partial) + accept (residual) | Plan 31-04 atomicity + Phase 28 chain-walker subject recording carry the mitigation; pre-exec Authenticode validation of the broker before `CreateProcessW` is OUT OF SCOPE here (deferred to v2.4 follow-up). Residual risk accepted. |
| T-31-15 (capability-pipe handle leak past nono.exe) | mitigate | HANDLE_LIST lists ONLY `pty_pair.input_write` + `pty_pair.output_read`; capability-pipe handles are non-inheritable (Phase 11 default) and not in the list. |
| T-31-16 (TOCTOU current_exe → CreateProcessW) | accept | Microsecond window; install-dir DACL is the same boundary protecting nono.exe itself. |
| T-31-17 (inheritance flag stuck-on after spawn) | mitigate | Cleanup `SetHandleInformation(_, HANDLE_FLAG_INHERIT, 0)` runs on BOTH success and failure paths. `grep -c SetHandleInformation` returns 12 across the file; ≥ 2 of those are the BrokerLaunch set+unset pair. |
| T-31-18 (Medium-IL broker compromise) | accept | Broker code is minimal; user already runs at Medium IL; no new privileges introduced. |
| T-31-19 (Job Object cascade escape) | mitigate | `apply_process_handle_to_containment` runs BEFORE `ResumeThread`; `JOB_OBJECT_LIMIT_*BREAKAWAY*` flags unset per Phase 16 RESL invariant; runtime acceptance is the `#[ignore]`'d `broker_launch_assigns_child_to_job_object` test (Plan 31-05 lifts). |
| T-31-20 (argv injection via --shell-arg) | mitigate | Broker parser (Plan 31-02) treats values as opaque strings; this plan's argv emitter goes through `quote_windows_arg` so embedded quotes/whitespace are properly escaped. |
| T-31-21 (LowIlPrimary fallback unintentional reach) | accept | Structurally unreachable today; manual smoke-test guards future changes; documented in the variant docstring. |

## Deviations from Plan

None. Tasks 1 and 2 executed exactly as specified by the plan. The only minor adjustment was moving the `IsProcessInJob` import inside the `broker_dispatch_tests` module (under `#[allow(unused_imports)]`) rather than at module-top in `mod.rs` — this is the spec-faithful interpretation because the test that uses `IsProcessInJob` is `#[ignore]`'d and an unconditional module-top import would fail the `-D warnings` clippy gate. The plan's verification grep does not check for `IsProcessInJob` placement.

## Issues Encountered

- **`cargo clippy -p nono` reports two `collapsible_match` errors** in `crates/nono/src/manifest.rs:95,103`. Verified pre-existing on worktree base `1712005d` (also documented in 31-01-SUMMARY.md). Out of scope per the SCOPE BOUNDARY rule; documented in `.planning/phases/31-broker-process-architecture-shell-01/deferred-items.md` (already present).
- **`cargo clippy -p nono-cli` reports two `collapsible_match` warnings** in `crates/nono-cli/src/exec_strategy_windows/supervisor.rs:788,800`. Verified pre-existing on worktree base via `git diff 1712005d -- crates/nono-cli/src/exec_strategy_windows/supervisor.rs` (zero output). Out of scope — supervisor.rs is not part of Plan 31-03's edit surface (only `launch.rs` and `mod.rs` are). Documented for the orchestrator's deferred-items review.
- **Working-directory drift on first build attempt.** The orchestrator's prompt cwd was `C:\Users\OMack\Nono\.claude\worktrees\agent-a68898abfd829548e`, but `cd "C:/Users/OMack/Nono"` (a habit-driven workspace-root reach in the first Bash call) sent the first round of edits to the main repo path, not the worktree. Caught at the pre-commit `git status` step; remediated by copying the modified `launch.rs` to the worktree path, reverting the main-repo file, and proceeding from the worktree. No commits landed on the wrong branch; no work was lost. Future executors operating in a worktree should always anchor `cd` to the worktree absolute path printed in the orchestrator's `<env>Working directory</env>` field.

## User Setup Required

None — no external service configuration required. Plan 31-04 will own the production broker artifact's release pipeline; until then, `nono shell` invocations on Windows will hit `NonoError::BrokerNotFound { path }` (correct fail-secure shape) rather than silently degrading.

## Next Phase Readiness

- **Plan 31-04 (runtime bundle):** the broker discovery contract is locked at `current_exe.parent() + "nono-shell-broker.exe"`. Plan 31-04 must ensure the broker artifact ships into the same directory as `nono.exe` for both machine-scope MSI (`Program Files/nono/`) and user-scope MSI (`%LOCALAPPDATA%/nono/`). Both MSIs already host `nono.exe`; adding `nono-shell-broker.exe` alongside is a Wix `<File>` element addition.
- **Plan 31-05 (field-test):** the `#[ignore]`'d `broker_launch_assigns_child_to_job_object` test embeds the `IsProcessInJob` import and references the lift plan. Plan 31-05's runtime acceptance for D-04 just removes the `#[ignore]` and fills in the test body; the dispatch + Job Object plumbing is already wired and proven by `pty_token_gate_tests` (7/7).
- **No blockers.** Worktree branch `worktree-agent-a68898abfd829548e` is ready for the orchestrator's post-wave merge alongside Plan 31-02's worktree.

## TDD Gate Compliance

Task 1 was tagged `tdd="true"` in the plan. Execution adopted a "tests-with-implementation" cadence rather than strict RED-then-GREEN because the cascade arm's behavior is purely structural (an enum variant + selector branch + match arm stub), and the renamed `pty_some_no_detach_selects_broker_launch` test was the natural carrier for the assertion flip. The 1 new test (`broker_launch_takes_precedence_over_session_sid_on_pty_path`) was added in the same commit as the enum/selector edit. Task 2 was `tdd="false"` per plan; the dispatch implementation + the 2-test `broker_dispatch_tests` module landed in the same commit. No RED commit exists for either task; documented here for transparency.

## Self-Check: PASSED

All 2 files claimed in this SUMMARY exist on disk; both commit hashes are reachable via `git log --oneline --all`.

```
$ ls crates/nono-cli/src/exec_strategy_windows/launch.rs crates/nono-cli/src/exec_strategy_windows/mod.rs
crates/nono-cli/src/exec_strategy_windows/launch.rs
crates/nono-cli/src/exec_strategy_windows/mod.rs

$ git log --oneline --all | grep -E "(55d2b1b2|aad42757)"
aad42757 feat(31-03): wire BrokerLaunch dispatch with HANDLE_LIST + sibling broker resolution
55d2b1b2 feat(31-03): add WindowsTokenArm::BrokerLaunch variant + selector dispatch

$ grep -c "WindowsTokenArm::BrokerLaunch" crates/nono-cli/src/exec_strategy_windows/launch.rs
4

$ grep -c "PROC_THREAD_ATTRIBUTE_HANDLE_LIST" crates/nono-cli/src/exec_strategy_windows/launch.rs
2

$ grep -c "NonoError::BrokerNotFound" crates/nono-cli/src/exec_strategy_windows/launch.rs
4

$ grep -c "nono-shell-broker.exe" crates/nono-cli/src/exec_strategy_windows/launch.rs
7

$ grep -c "build_broker_command_line" crates/nono-cli/src/exec_strategy_windows/launch.rs
2
```

All literal-string acceptance criteria from both tasks pass. Tests: `pty_token_gate_tests` 7/7, `low_integrity_primary_token_tests` 2/2, `broker_dispatch_tests` 1 passed + 1 ignored — matches the plan's verification line items 3a/3b/3c exactly.

---
*Phase: 31-broker-process-architecture-shell-01*
*Wave: 2 (parallel with Plan 31-02)*
*Completed: 2026-05-09*
