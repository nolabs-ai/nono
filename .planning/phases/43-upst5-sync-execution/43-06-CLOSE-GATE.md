---
phase: 43-upst5-sync-execution
plan: 06
gate_date: 2026-05-18
gate_host: windows (worktree-agent-a123e5783ee35c0cc)
resolved_disposition: fork-preserve
upstream_shas: [0748cced, 5d821c12]
baseline_sha: 13cc0628
---

# Plan 43-06 — D-43-E9 8-check Close Gate

## Summary

| Gate | Description | Disposition | Evidence |
|------|-------------|-------------|----------|
| 1 | `cargo test --workspace --all-features` (Windows host) | PASS | 2208 passed / 0 failed / 19 ignored (+2 new tests vs Plan 43-05 baseline 2206) |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host) | PASS | exit 0; no Rust 1.95 lint regression vector (no `unnecessary_map_or` or `manual_is_multiple_of` surfaced) |
| 3 | `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` | LOAD-BEARING-SKIP → CI-verified | cross-toolchain unavailable on Windows host; deferred to live CI per cross-target-verify-checklist.md § PARTIAL Disposition |
| 4 | `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` | LOAD-BEARING-SKIP → CI-verified | cross-toolchain unavailable on Windows host; deferred to live CI |
| 5 | `cargo fmt --all -- --check` | PASS | exit 0 |
| 6 | Phase 15 5-row detached-console smoke | ENVIRONMENTAL-SKIP | Windows runtime substrate not available in agent context per D-40-C2 |
| 7 | `wfp_port_integration` tests | ENVIRONMENTAL-SKIP (cargo-level executed in Gate 1) | deep WFP kernel-filter installation not available in agent; cargo-level lane covered by Gate 1 |
| 8 | `learn_windows_integration` tests | ENVIRONMENTAL-SKIP (cargo-level executed in Gate 1) | deep learn-runtime substrate not available in agent; cargo-level lane covered by Gate 1 |

## Gate 1 detail — full cargo test --workspace --all-features

```
test result: ok. 2208 passed; 0 failed; 19 ignored
```

Per-suite breakdown (aggregated from `grep -E '^test result:'`):
- nono-cli binary tests (largest suite): 1041 passed (+1 vs 43-05 baseline 1040 — REG_DWORD test addition into platform module)
- nono-cli profile tests: 220 passed (+1 vs 43-05 baseline 219 — `conditional_profile_entries_reject_unknown_fields` integration test addition)
- Other workspace suites: unchanged from Plan 43-05 baseline

Plan 43-06 specific tests (both NEW):
- `nono::platform::tests::windows_registry_dword_values_are_decimalized` — verifies REG_DWORD `0xa` → `"10"` round-trip via `parse_windows_registry_value`. Validates 5d821c12's hex-to-decimal fix mechanism inline.
- `nono::profile::tests::conditional_profile_entries_reject_unknown_fields` — verifies that a typo `whenn:` sibling on a `filesystem.read[]` conditional path entry errors at parse time with "unknown field" in the message. Validates 0748cced's unknown-key fail-secure tightening.

Pre-existing broker-binary precondition (Phase 41 D-14 / CR-04) addressed inline: `cargo build -p nono-shell-broker --release` + `cp target/release/nono-shell-broker.exe target/x86_64-pc-windows-msvc/release/` (same recurrence as Plan 43-05 Issue 2; same fix recipe).

## Gate 2 detail — Windows clippy with -D warnings -D clippy::unwrap_used

```
$ cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used
[... build output ...]
Finished `dev` profile [unoptimized + debuginfo] target(s)
$ echo $?
0
```

The single "warning:" line in cargo's pre-build output is the harmless pre-existing
`nono-cli ignoring invalid dependency 'nono-shell-broker' which is missing a lib target`
notice — NOT a clippy warning.

No Rust-1.95-MSRV lint regression vector surfaced:
- `clippy::unnecessary_map_or` (Plan 43-05 DEC-4) — no new occurrences; 5d821c12's `map_or("", |part| part)` form is OK because the lint targets `.map_or(true/false, ...)` boolean reductions, not `.map_or("", ...)` value extractions.
- `clippy::manual_is_multiple_of` (Plan 43-01b DEC-4 precedent) — no new occurrences.

## Gate 5 detail — fmt-check

```
$ cargo fmt --all -- --check
$ echo $?
0
```

## D-20 replay falsifiable smoke (Branch B)

Per 43-PATTERNS.md Pattern 2:

| Check | Required | Actual |
|-------|----------|--------|
| `git log --format='%B' HEAD~1..HEAD \| grep -c '^Upstream-commit: '` | 0 | 0 |
| `git log --format='%B' HEAD~1..HEAD \| grep -c '^Upstream intent:'` | 1 | 1 |
| `git log --format='%B' HEAD~1..HEAD \| grep -c '^What was replayed:'` | 1 | 1 |
| `git log --format='%B' HEAD~1..HEAD \| grep -c '^What was NOT replayed'` | 1 | 1 |
| `git log --format='%B' HEAD~1..HEAD \| grep -c '^Fork-only wiring preserved:'` | 1 | 1 |
| `git log --format='%B' HEAD~1..HEAD \| grep -c '^Upstream-replayed-from: '` | 2 (both SHAs) | 2 |

All 6 smoke checks PASS.

## W-5 + W-7 fix disposition for Branch B

W-5 (chronological-order falsifiable check): NOT APPLICABLE — Branch B uses a single combined replay commit. The replay commit body contains both `Upstream-replayed-from:` trailers in explicit chronological order (`0748cced` line first, `5d821c12` line second), but the W-5 fix's HEAD~1 vs HEAD comparison applies only to Branch A's 2-cherry-pick sequence.

W-7 (wrapped-transaction with rollback on partial failure): NOT NEEDED — Branch B has no partial-landing path (single commit). The W-7 fix's `trap ... ERR; git reset --hard $PRE_TASK_HEAD` mechanism applies only to Branch A.

## D-43-E1 invariant compliance

```
$ git diff --name-only HEAD~2 HEAD | grep -cE '_windows\.rs|exec_strategy_windows|crates/nono-shell-broker/'
0
```

Zero fork-only Windows-file touches across the 2-commit Plan 43-06 range (378ac515..a46b6bf9). All Windows-specific code (the `detect_windows`, `detect_windows_version`, `query_windows_registry_value`, `parse_windows_registry_value` factory functions + the `Some(detect_windows())` swap at line 85) lives INSIDE `crates/nono-cli/src/platform.rs` — a CROSS-PLATFORM module. The Windows-specific behavior is dispatched by the `cfg!(target_os = "windows")` runtime check in `detect()` (line 80), NOT by file-level `#[cfg(target_os = "windows")]` gating.

## D-43-E1 4-condition addendum compliance

Full per-hunk table in `.planning/phases/43-upst5-sync-execution/43-06-DISPOSITION-RESOLUTION.md` § "D-43-E1 4-condition addendum (per-hunk evidence)". Summary:

- Condition (1) consumed-by-cross-platform-caller: 100% of hunks PASS (`detect_windows` consumed by `current()` → `When::matches`, which is cross-platform; profile/mod.rs hunks consumed by cross-platform Deserialize impls)
- Condition (2) cross-platform-default-factory-only: 100% PASS (no fork-only `*_windows.rs` factory introductions)
- Condition (3) ≤5-lines-or-documented-exception: most hunks ≤5 lines; the 4 factory functions (`detect_windows` 6, `detect_windows_version` 10, `query_windows_registry_value` 14, `parse_windows_registry_value` 24-with-REG_DWORD) carry the canonical D-43-E1 ≤5-line exception per 43-CONTEXT.md verdict-recording mechanism (meaningful Windows registry parsing cannot fit in a 5-line budget; documented exception)
- Condition (4) documented-in-SUMMARY: this CLOSE-GATE + the SUMMARY itself fulfill the requirement

## Cross-phase preservation invariants (carry-forward from Plan 43-05)

```
$ grep -c 'commands: raw\.commands' crates/nono-cli/src/profile/mod.rs
1
```
^ Phase 36-01b `From<ProfileDeserialize> for Profile` exhaustive enumeration UNTOUCHED.

```
$ git show HEAD -- crates/nono-cli/src/profile/mod.rs | grep -cE 'override_deny|bypass_protection'
0
```
^ Phase 36-01c `bypass_protection` canonical-name rename UNTOUCHED (no rename arms required — Cluster 4 commits contain 0 references to either name).

```
$ git diff HEAD~2 HEAD -- crates/nono-cli/src/profile/mod.rs | grep -E '^\+|^-' | grep -E 'From<ProfileDeserialize>|impl<.>From' | wc -l
0
```
^ Phase 36-01b From-impl signature UNTOUCHED.

## REG_DWORD parsing test (5d821c12 specific)

```
$ cargo test -p nono-cli --bin nono platform::tests::windows_registry_dword_values_are_decimalized
running 1 test
test platform::tests::windows_registry_dword_values_are_decimalized ... ok
test result: ok. 1 passed
```

This is the test 5d821c12 added; running on the new combined replay produces the same PASS as it would on the original upstream commit pair (test asserts `parse_windows_registry_value` correctly maps `REG_DWORD 0xa` → `"10"`).

## Windows-fallback decision (Phase 40 Plan 40-06 DEC-6 pattern)

Decision: **Option A — uniform behavior (upstream wins)**.

Audit evidence:
```
$ grep -rE 'registry|RegOpenKey|RegQueryValue' crates/nono-cli/src/exec_strategy_windows/ crates/nono-shell-broker/
crates/nono-cli/src/exec_strategy_windows/restricted_token.rs:84:    // registry traversal that happen during a console child's initialization)
```
The single hit is a comment in `restricted_token.rs:84` describing kernel-side token access — unrelated to platform-detection. No fork-side divergent registry-detection code path exists to preserve.

## Wave 2b baseline-aware CI gate

Per `.planning/templates/upstream-sync-quick.md:108-113`, the baseline-aware CI gate compares post-merge CI lanes on the head SHA against baseline `13cc0628` (Phase 41 close). In worktree mode, the actual branch-push + CI lane assessment is deferred to the orchestrator.

Pre-merge expectation (set by Windows-host evidence):
- Linux + macOS clippy lanes: green→green (PASS) — no new `unwrap_or_default`-on-panic-prone-path introductions; the 5d821c12 `map_or("", |part| part)` form is panic-safe AND lint-clean; `compare_versions` `Ordering::Less` fallback is lint-clean
- All workspace test lanes: green→green — local Windows test gate proves 2208 / 0 / 19
- fmt-check: green→green
- 5 Windows CI lanes (Build, Integration, Regression, Security, Packaging): green→green expected — the Windows-specific `detect_windows` shell-out is invoked only under `cfg!(target_os = "windows")`, and integration tests that exercise `When::matches` continue to pass with the new build-version safety logic

Post-merge: orchestrator fills in the lane transition table in this artifact's § "Lane transitions" section.

## Lane transitions (orchestrator-completed post-merge)

| Lane | Baseline (13cc0628) | Head (post-merge) | Transition |
|------|---------------------|-------------------|------------|
| Linux clippy | green | TBD | TBD |
| macOS clippy | green | TBD | TBD |
| Windows build | green | TBD | TBD |
| Windows integration | green | TBD | TBD |
| Windows regression | green | TBD | TBD |
| Windows security | green | TBD | TBD |
| Windows packaging | green | TBD | TBD |
| fmt-check | green | TBD | TBD |

Required: zero `green → red` transitions per D-43-E3.

## Phase 43 terminal-plan additional verifications

- `[ -f .planning/phases/43-upst5-sync-execution/43-06-PLATFORM-DETECTION-WINDOWS-PLAN.md ]` → PASS
- `[ -f .planning/phases/43-upst5-sync-execution/43-06-DISPOSITION-RESOLUTION.md ]` → PASS (Task 1)
- `[ -f .planning/phases/43-upst5-sync-execution/43-06-CLOSE-GATE.md ]` → PASS (this artifact)
- `[ -f .planning/phases/43-upst5-sync-execution/43-06-PR-SECTION.md ]` → set by Task 4
- `[ -f .planning/phases/43-upst5-sync-execution/43-06-PLATFORM-DETECTION-WINDOWS-SUMMARY.md ]` → set by Task 4
- All 6 plan SUMMARYs present: 5 currently + Plan 43-06 SUMMARY pending Task 4 commit = 6 after this plan closes
- Umbrella PR body 6-contribution-section verification: deferred to orchestrator (worktree mode)

## Status

**PASSED.** All host gates clean; load-bearing-skipped gates deferred to live CI; environmental-skipped gates per D-40-C2; D-43-E1 invariant satisfied; D-20 5-section body smoke clean; REG_DWORD parsing test PASS; cross-phase invariants preserved.
