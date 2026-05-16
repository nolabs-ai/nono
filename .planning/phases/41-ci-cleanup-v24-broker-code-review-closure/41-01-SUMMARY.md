---
phase: 41-ci-cleanup-v24-broker-code-review-closure
plan: "01"
subsystem: nono-cli (exec_strategy.rs — supervisor IPC handler)
tags: [api-migration, deprecated-field, clippy, CapabilityRequest, HandleTarget]
dependency_graph:
  requires: []
  provides: [request_path-helper, 14-sites-migrated]
  affects: [Phase-37-rebase-surface]
tech_stack:
  added: []
  patterns: [deprecated-field-localization, private-helper-spike-then-bulk]
key_files:
  created: []
  modified:
    - crates/nono-cli/src/exec_strategy.rs
decisions:
  - "D-04 spike-then-bulk honored: Task 1 migrated site 2662 only; Task 2 bulk-applied remaining 13"
  - "D-06 cross-target clippy: Windows-host Linux cross-target blocked by missing x86_64-linux-gnu-gcc (ring/aws-lc-sys C build dependencies); Windows-native clippy passes; deferred to CI"
  - "Helper placed at line 2634 (above handle_supervisor_message) as fn request_path() with #[allow(deprecated)] scoped to fallback arm only"
metrics:
  duration: "~30 minutes"
  completed: "2026-05-15"
  tasks_completed: 2
  tasks_total: 2
  files_changed: 1
---

# Phase 41 Plan 01: CapabilityRequest::path Migration Summary

**One-liner:** Private `request_path()` helper with `HandleTarget::FilePath` fallback localizes 14 deprecated `CapabilityRequest::path` reads in `exec_strategy.rs` to a single `#[allow(deprecated)]` site.

## What Was Built

Migrated all 14 `CapabilityRequest::path` field reads inside `handle_supervisor_message()` in `crates/nono-cli/src/exec_strategy.rs` to use a new private helper `fn request_path(request: &nono::CapabilityRequest) -> &std::path::Path`. The helper extracts the path from `HandleTarget::FilePath { path }` when the AIPC-01 wire shape is present, falling back to the deprecated `path` field for Phase 11-shaped requests.

## Sites Migrated

### Helper placement
- **File:line:** `crates/nono-cli/src/exec_strategy.rs:2634`
- **Position:** Above `handle_supervisor_message`

### Shape 1 — Owned PathBuf into DenialRecord (7 sites total, including Task 1 spike)
| Original line | Site description |
|--------------|------------------|
| 2662 (Task 1 spike) | Replay detection DenialRecord |
| 2696 | Protected root DenialRecord |
| 2729 | Trust verified + user-denied DenialRecord |
| 2742 | Trust backend error DenialRecord |
| 2763 | Trust verify fail DenialRecord |
| 2781 | Approval non-instruction user-denied DenialRecord |
| 2794 | Approval non-instruction backend error DenialRecord |

Transform: `request.path.clone()` → `request_path(&request).to_path_buf()`

### Shape 2 — Display in debug!/format! macros (4 sites)
| Original line | Site description |
|--------------|------------------|
| 2690 | Protected root debug! path display |
| 2705 | Protected root format! reason display |
| 2717 | Trust verified debug! path display |
| 2757 | Trust verify fail debug! path display |

Transform: `request.path.display()` → `request_path(&request).display()`

### Shape 3 — &Path parameter pass (3 sites)
| Original line | Site description |
|--------------|------------------|
| 2684 | `overlapping_protected_root()` call |
| 2710 | `ti.check_path()` call |
| 2809 | `open_path_for_access()` call |

Transform: `&request.path` → `request_path(&request)`

## Cross-target Clippy Commands Run

| Target | Command | Outcome |
|--------|---------|---------|
| x86_64-pc-windows-msvc | `cargo clippy --package nono-cli --target x86_64-pc-windows-msvc -- -D warnings -D clippy::unwrap_used` | EXIT 0 — Finished `dev` profile with no warnings |
| x86_64-unknown-linux-gnu | `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` | FAILED at build — `ring` and `aws-lc-sys` require `x86_64-linux-gnu-gcc` which is not installed on this Windows host; Rust type-checking was blocked at C FFI compilation stage |
| x86_64-apple-darwin | Not attempted — macOS cross-toolchain unavailable on Windows host | Deferred to CI |

**Note on cross-target Linux:** The failure is a C cross-compiler toolchain gap (no `x86_64-linux-gnu-gcc`), NOT a Rust type error. The `exec_strategy.rs` file is pure Rust with no C dependencies; the Rust type checker would succeed if the C build scripts could complete. Windows-native clippy confirms zero Rust-level warnings in the migrated code. The CI Linux Clippy lane will provide the authoritative Linux gate.

## Build and Test Verification

| Check | Command | Result |
|-------|---------|--------|
| Build | `cargo build --workspace --target x86_64-pc-windows-msvc` | EXIT 0 — all 5 crates compiled |
| Unit tests | `cargo test -p nono-cli --bin nono` | EXIT 0 — 1011 passed, 0 failed |
| Clippy (Windows) | `cargo clippy --package nono-cli -- -D warnings -D clippy::unwrap_used` | EXIT 0 |

## Acceptance Criteria Status

| Criterion | Status |
|-----------|--------|
| `fn request_path` exists exactly once | PASS — `grep -c` returns 1 |
| Site 2662 area now reads `request_path(&request).to_path_buf()` | PASS — confirmed at line 2677 (shifted after helper insertion) |
| Zero `request.path` reads outside `fn request_path` | PASS — grep returns 0 |
| `request_path(&request)` appears >= 14 times | PASS — grep -c returns 14 |
| Windows clippy exits 0 | PASS |
| Linux clippy exits 0 | DEFERRED to CI (C cross-compiler not available on Windows host) |
| Unit tests pass | PASS — 1011/1011 |
| Build passes | PASS |
| DCO sign-off on both commits | PASS |

## Phase 37 Rebase Surface

Phase 37 (parallel) can now rebase on the post-migration `exec_strategy.rs`. The `handle_supervisor_message` function signature is unchanged. The only diff is:
1. A new `fn request_path()` helper at line 2634
2. All 14 `request.path` reads replaced with `request_path(&request)` calls

No API surface changes, no import additions at module scope, no behavior changes.

## Deviations from Plan

**1. [Rule 3 - Environment] Cross-target Linux clippy blocked by missing C cross-compiler**
- **Found during:** Task 1 verification
- **Issue:** `cargo clippy --workspace --target x86_64-unknown-linux-gnu` failed because `ring` and `aws-lc-sys` build scripts require `x86_64-linux-gnu-gcc` which is not installed on the Windows host. This is a build-time C compilation failure, not a Rust type-check failure.
- **Fix:** Ran Windows-native clippy (`x86_64-pc-windows-msvc`) which covers the same Rust-level lint surface for this pure-Rust file. Linux gate deferred to CI per plan's own note: "macOS cross-target may fall back to CI runner if the local toolchain is unavailable."
- **Files modified:** None (environment limitation, not code issue)
- **Impact:** The Linux Clippy CI lane is the authoritative gate; this is not a security concern as no C code was changed.

## Known Stubs

None — this is a pure refactoring change with no new data sources, UI, or placeholder values.

## Threat Flags

None — the migration preserves identical semantic values at all 14 capability-decision sites. The helper's fallback arm (`_ => { #[allow(deprecated)] { &request.path } }`) ensures Phase 11-shaped requests (where `target` is `None`) continue to use the same path value as before. No new network endpoints, auth paths, file access patterns, or schema changes introduced.

## Self-Check: PASSED

| Item | Status |
|------|--------|
| exec_strategy.rs exists | FOUND |
| 41-01-SUMMARY.md exists | FOUND |
| Commit 22f96764 (Task 1) | FOUND |
| Commit c89d7e79 (Task 2) | FOUND |
| fn request_path count = 1 | PASS |
| request_path call count = 14 | PASS |
| Remaining request.path outside helper = 0 | PASS |
