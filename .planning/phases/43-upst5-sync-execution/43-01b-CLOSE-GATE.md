# Plan 43-01b Close Gate Evidence (D-43-E9 / 8-check format)

**Plan:** 43-01b-EDITION-WORKSPACE-ONLY
**Recorded:** 2026-05-18
**Head SHA:** `2603c7a6` (`fix(43-01b): adopt is_multiple_of() ...`)
**Baseline SHA:** `13cc0628` (Phase 41 close, all CI lanes green)
**Toolchain:** rustc 1.95.0 (59807616e 2026-04-14) / cargo 1.95.0 (f2d3ce0bd 2026-03-21)

## Commit chain (3 commits, 79715aa5..2603c7a6)

| Order | Hash       | Type   | Subject                                                          |
|-------|------------|--------|------------------------------------------------------------------|
| 1     | `b6aac925` | chore  | centralize nix/landlock/getrandom deps + bump MSRV to 1.95       |
| 2     | `f97d6561` | chore  | regenerate Cargo.lock post-workspace-deps centralization         |
| 3     | `2603c7a6` | fix    | adopt is_multiple_of() for rust 1.95 clippy lint compliance      |

## Gate-by-gate disposition

### Gate 1 — `cargo test --workspace --all-features` (Windows host) — REQUIRED → PASS

```
=== total test result summary ===
2197 passed; 0 failed; 19 ignored; 0 measured; 0 filtered out
```

40 separate test-runner result lines, all `ok. ... 0 failed`. Notable counts:
- nono lib: 689 passed
- nono manifest tests: 40 + 16 passed
- nono-cli bin: 1031 passed
- nono-cli integration tests (40 binaries): combined ~280 passed
- nono-ffi unit tests: 41 passed
- nono-proxy unit tests: 148 passed
- nono-shell-broker unit tests: 15 passed
- nono doc-tests: 8 passed

Note re Phase 41 D-14 / CR-04 broker-binary prerequisite: first `cargo test` run
failed `broker_launch_assigns_child_to_job_object` because
`target/release/nono-shell-broker.exe` was absent (CR-04 documented Failure mode).
After `cargo build -p nono-shell-broker --release`, full test re-run passes.
This is an environment-setup precondition, NOT a 43-01b regression.

### Gate 2 — `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host) — REQUIRED → PASS

Initial run after b6aac925 + f97d6561 surfaced 10 NEW `clippy::manual_is_multiple_of`
errors (lint stabilized in rust 1.95; surfaced by the MSRV bump from 1.77).

Rule 3 (auto-fix blocking issue) deviation: 10 mechanical `% N == 0` → `.is_multiple_of(N)`
rewrites applied as commit `2603c7a6`. All 4 affected files documented in commit body
and SUMMARY DEC-4.

Final clippy run (post-2603c7a6):

```
Checking nono v0.53.0
Checking nono-cli v0.53.0
Checking nono-proxy v0.53.0
Checking nono-shell-broker v0.53.0
Checking nono-ffi v0.53.0
Finished `dev` profile [unoptimized + debuginfo] target(s) in 12.14s
```

Zero errors. Note: `warning: nono-cli v0.53.0 ... ignoring invalid dependency
nono-shell-broker which is missing a lib target` is a known Phase 41 D-14 cosmetic
warning, not a clippy lint failure.

### Gate 3 — `cargo clippy --workspace --target x86_64-unknown-linux-gnu` — LOAD-BEARING → SKIP-PARTIAL → CI-verified

Disposition: **load-bearing-skip → CI-verified** per
`.planning/templates/cross-target-verify-checklist.md` § PARTIAL Disposition.

Skip reason: cross-target clippy gate SKIPPED on Windows dev host due to missing
toolchain (`x86_64-linux-gnu-gcc` not found; rustup target IS installed but the
C linker required by native-link crates like `aws-lc-sys` / `ring` is absent on
the Windows host). The live GH Actions Linux Clippy lane on the head SHA `2603c7a6`
is the decisive signal per the checklist. Plan frontmatter declared this skip
class up-front: `skipped_gates_load_bearing: [3, 4]`.

CI-substitute: GH Actions Linux Clippy lane on the umbrella PR head SHA must report
no `-D warnings -D clippy::unwrap_used` errors before this gate is verified.

### Gate 4 — `cargo clippy --workspace --target x86_64-apple-darwin` — LOAD-BEARING → SKIP-PARTIAL → CI-verified

Disposition: **load-bearing-skip → CI-verified**.

Skip reason: cross-target clippy gate SKIPPED on Windows dev host due to missing
toolchain (`cc` not found for macOS cross-link; rustup target IS installed but
the macOS linker stack is unavailable on Windows). Same PARTIAL Disposition prose
as Gate 3 applies.

CI-substitute: GH Actions macOS Clippy lane on the umbrella PR head SHA must report
no errors before this gate is verified.

### Gate 5 — `cargo fmt --all -- --check` — REQUIRED → PASS

```
$ cargo fmt --all -- --check
$ echo $?
0
```

No formatting drift.

### Gate 6 — Phase 15 5-row detached-console smoke — ENVIRONMENTAL → SKIP

Disposition: **environmental-skip** per Phase 40 D-40-C2 precedent. Windows
runtime substrate for the Phase 15 5-row attach smoke (real console attach,
real PTY pump, real session.json roundtrip) is not available in the agent
worktree context. Plan frontmatter declared this skip class up-front:
`skipped_gates_environmental: [6, 7, 8]`.

Phase 40 precedent: D-40-C2 documented the same skip for proxy / TLS-flavored
plans where the Windows runtime substrate was not available. The CI Windows
Smoke lane substitutes.

### Gate 7 — `wfp_port_integration` tests — ENVIRONMENTAL → SKIP (with caveat)

Disposition: **environmental-skip** per Phase 40 D-40-C2 precedent.

Caveat: the `wfp_port_integration` test binary DID run as part of Gate 1's
workspace test run (line: `Running tests\wfp_port_integration.rs ... test result:
ok. 2 passed; 0 failed; 1 ignored`). The "environmental" qualifier applies
specifically to the requirement of real WFP kernel filter installation, which
would need an elevated process + WFP service installation. The cargo-level
tests that DO run are passing; the deep WFP integration depth is not exercised
in the agent context.

### Gate 8 — `learn_windows_integration` tests — ENVIRONMENTAL → SKIP (with caveat)

Disposition: **environmental-skip** per Phase 40 D-40-C2 precedent.

Caveat: same as Gate 7 — the `learn_windows_integration` test binary DID run
in Gate 1 (line: `Running tests\learn_windows_integration.rs ... test result:
ok. 60 passed; 0 failed; 14 ignored`). The 14 ignored tests are the ones that
require real `learn` mode runtime substrate (file-mode probes, IL boundary
checks). Cargo-level tests pass; deeper runtime substrate not exercised.

## Wave 0a baseline-aware CI gate (D-43-E3 / `.planning/templates/upstream-sync-quick.md:108-113`)

**Baseline SHA:** `13cc0628` (Phase 41 close)
**Head SHA:** `2603c7a6` (this plan's HEAD)
**Commits between:** 3 (b6aac925, f97d6561, 2603c7a6)

Branch push status: **DEFERRED to orchestrator** (worktree-mode; Task 5 step 4
defers branch push and umbrella PR open to the orchestrator post-merge).

Per-lane diff vs baseline `13cc0628` — to be filled in by orchestrator after CI
runs on the umbrella PR head SHA:

| CI Lane                       | Baseline (13cc0628) | Head (post-merge) | Transition       |
|-------------------------------|---------------------|-------------------|------------------|
| Linux Clippy                  | green               | TBD               | TBD              |
| macOS Clippy                  | green               | TBD               | TBD              |
| Linux Test                    | green               | TBD               | TBD              |
| macOS Test                    | green               | TBD               | TBD              |
| Windows Build                 | green               | TBD               | TBD              |
| Windows Integration           | green               | TBD               | TBD              |
| Windows Regression            | green               | TBD               | TBD              |
| Windows Security              | green               | TBD               | TBD              |
| Windows Packaging             | green               | TBD               | TBD              |
| fmt-check                     | green               | TBD               | TBD              |

**Expected:** all lanes green→green (PASS). The Rule 3 deviation in commit `2603c7a6`
specifically forecloses the most-likely Linux/macOS Clippy regression vector
(clippy::manual_is_multiple_of) that the MSRV bump would otherwise trigger.

**Acceptance rule (D-43-E3):** zero `success → failure` transitions. red→red
carry-forwards from baseline are not gating; green→green confirms parity.

## Summary

- Gate 1: PASS (2197 tests, 0 failures)
- Gate 2: PASS (after Rule 3 deviation commit 2603c7a6)
- Gate 3: load-bearing-skip → CI-verified
- Gate 4: load-bearing-skip → CI-verified
- Gate 5: PASS (no formatting drift)
- Gate 6: environmental-skip
- Gate 7: environmental-skip (cargo-level tests in Gate 1 pass)
- Gate 8: environmental-skip (cargo-level tests in Gate 1 pass)
- Wave 0a CI gate: deferred to orchestrator post-merge

D-43-E9 close-gate format honored. All required gates pass; all skips properly
categorized per the cross-target-verify-checklist + Phase 40 D-40-C2 precedents.
