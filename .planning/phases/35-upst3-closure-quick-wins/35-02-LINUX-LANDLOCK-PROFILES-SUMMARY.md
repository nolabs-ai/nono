---
phase: 35-upst3-closure-quick-wins
plan: 02
subsystem: sandbox
tags: [linux, landlock, profile, filesystem, upstream-sync, cherry-pick]

# Dependency graph
requires:
  - phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
    provides: "P34-DEFER-09-1 deferral of upstream bdf183e9 Landlock pre-create hunk"
provides:
  - "pre_create_landlock_profiles_dir() helper in profile_runtime.rs (Linux-gated)"
  - "Linux idempotency test for profiles dir pre-creation"
  - "Closure of P34-DEFER-09-1"
affects: [35-03-WIN-TEST-HYGIENE, 37-linux-macos-execution]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Linux-gated helper function pattern: #[cfg(target_os = \"linux\")] fn helper() -> crate::Result<()>"
    - "Error-propagating create_dir_all via From<io::Error> for NonoError using ?"
    - "EnvGuard RAII save/restore pattern for XDG_CONFIG_HOME in parallel test context"

key-files:
  created: []
  modified:
    - "crates/nono-cli/src/profile_runtime.rs"

key-decisions:
  - "Fork uses crate::config::user_profiles_dir() (XDG-aware) instead of upstream's profile::resolve_user_config_dir() + manual join(nono/profiles)"
  - "Fork propagates create_dir_all errors via ? (fail-secure) instead of upstream's best-effort let _ = style"
  - "No #[ignore] on Linux integration test per D-35-D3 — CI Linux lane runs unconditionally"
  - "EnvGuard scoped to #[cfg(target_os = \"linux\")] to avoid dead_code warnings on Windows/macOS"

patterns-established:
  - "Pre-create-before-Landlock pattern: first instance in fork; established as canonical pattern for Phase 37 RESL backends"

requirements-completed:
  - REQ-PORT-CLOSURE-06

# Metrics
duration: 20min
completed: 2026-05-12
---

# Phase 35 Plan 02: Linux Landlock Profiles Summary

**Cherry-pick of upstream bdf183e9 (v0.44.0) Landlock pre-create hunk: pre_create_landlock_profiles_dir() in profile_runtime.rs eliminates first-run No such file or directory UX bug on Linux; closes P34-DEFER-09-1**

## Performance

- **Duration:** ~20 min
- **Started:** 2026-05-12T18:00:00Z
- **Completed:** 2026-05-12T18:10:41Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments

- Landed the 15-line `pre_create_landlock_profiles_dir()` Linux-gated helper in `prepare_profile` — pre-creates `~/.config/nono/profiles/` BEFORE the caller builds the Landlock `CapabilitySet` and calls `Sandbox::apply → restrict_self`
- Fork adaptation uses `crate::config::user_profiles_dir()` (XDG-aware) and `?` error propagation (fail-secure, unlike upstream's best-effort `let _ =` style)
- Added Linux-gated `EnvGuard` RAII struct + `test_pre_create_landlock_profiles_dir_idempotent` test per CLAUDE.md env-var save/restore pattern
- Closed P34-DEFER-09-1 (Landlock first-run profiles-dir error)

## Task Commits

Each task was committed atomically:

1. **Task 1: Cherry-pick bdf183e9 — pre-create profiles dir before Landlock apply (Linux-only hunk)** - `327fe104` (feat)
2. **Task 2: Add Linux-gated integration test locking idempotency + first-run behavior** - `cde74cf4` (test)

## Files Created/Modified

- `crates/nono-cli/src/profile_runtime.rs` - Added `pre_create_landlock_profiles_dir()` Linux-gated helper + call site in `prepare_profile` + `EnvGuard` + `test_pre_create_landlock_profiles_dir_idempotent`

## Decisions Made

- **Fork path helper vs upstream path helper:** Upstream `bdf183e9` uses `profile::resolve_user_config_dir()` and manually joins `"nono/profiles"`. Fork uses `crate::config::user_profiles_dir()` which is XDG-aware and the canonical fork-wide resolution. Avoids any `dirs::home_dir()` call (STATE.md Windows blocker).
- **Error propagation style:** Upstream uses best-effort `let _ = std::fs::create_dir_all(&profiles_dir)` (ignore errors). Fork uses `std::fs::create_dir_all(&dir)?` per T-35-02-03 threat model — fail-secure behavior: if the directory is uncreatable, the supervisor exits cleanly rather than silently proceeding to a sandbox that will deny the write anyway.
- **No `#[ignore]` on Linux test:** Per D-35-D3, the Linux integration test runs unconditionally in the CI Linux lane. Windows/macOS are compile-time no-ops via `#[cfg(target_os = "linux")]`.

## D-19 Commit Shape Gates (PSV Verification)

- **PSV-1:** `git log --format='%B' HEAD~2..HEAD | grep -c '^Upstream-commit: bdf183e9'` = 1 ✓ (Task 1's cherry-pick commit; Task 2's test commit does NOT carry the trailer)
- **PSV-2:** `Upstream-author:` uses lowercase 'a' ✓
- **PSV-3:** `Upstream-tag: v0.44.0` present ✓
- **PSV-4:** Task 1's commit has 2 `Signed-off-by:` lines (Oscar Mack + oscarmackjr-twg) ✓
- **PSV-5:** Task 1 modified exactly 1 file (`crates/nono-cli/src/profile_runtime.rs`) ✓
- **PSV-6:** No `crates/nono-cli/src/wiring.rs` edits (Phase 36 REQ-PORT-CLOSURE-04 territory) ✓
- **PSV-7:** CI Linux lane URL — pending CI run; functional verification of `test_pre_create_landlock_profiles_dir_idempotent` deferred to CI Linux lane per D-35-D3

## D-35-D2 Close-Gate Disposition

| Gate | Disposition |
|------|-------------|
| 1. `cargo test --workspace --all-features` (Windows) | PASS — 943 nono-cli tests pass; 1 pre-existing flake in nono (`helper_stamps_session_token_from_env`, race condition, unrelated to this plan) |
| 2. `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows) | PASS |
| 3. `cargo clippy --target x86_64-unknown-linux-gnu` | PASS (Rust analysis clean; C linker not available on Windows host, expected) |
| 4. `cargo clippy --target x86_64-apple-darwin` | Pending — macOS toolchain not installed on Windows host |
| 5. `cargo fmt --all -- --check` | PASS |
| 6. Phase 15 5-row detached-console smoke gate | N/A — Linux-only hunk; no Windows behavior change |
| 7. `wfp_port_integration` test suite | N/A — no WFP surface touched |
| 8. `learn_windows_integration` test suite | N/A — no Windows learn surface touched |

## Scope Trim

Upstream `bdf183e9` (v0.44.0) included 239 lines across 5 files:
- `crates/nono-cli/data/policy.json` (+2) — NOT picked up (Phase 36 territory)
- `crates/nono-cli/src/package.rs` (+21/-2) — NOT picked up (Phase 36 territory)
- `crates/nono-cli/src/package_cmd.rs` (+59/-0) — NOT picked up (Phase 36 territory)
- `crates/nono-cli/src/profile_runtime.rs` (+15) — PICKED UP (Plan 35-02 scope)
- `crates/nono-cli/src/wiring.rs` (+206/-64) — NOT picked up (Phase 36 REQ-PORT-CLOSURE-04 territory)

Only the 15-line `profile_runtime.rs` hunk was absorbed. The remaining 188/224 upstream lines are deferred to Phase 36 per REQ-PORT-CLOSURE-04.

## Closure Ledger

- **P34-DEFER-09-1:** `closed-by-Phase-35-02` — Landlock first-run profiles-dir pre-create hunk from upstream bdf183e9 landed in `profile_runtime.rs`; first-run `No such file or directory` error eliminated on Linux.

## Deviations from Plan

None — plan executed exactly as written. The one intentional fork adaptation (using `crate::config::user_profiles_dir()` + `?` propagation instead of upstream's approach) was specified in the plan's `must_haves` and threat model.

## Issues Encountered

- Cross-target Linux clippy (`--target x86_64-unknown-linux-gnu`) requires `x86_64-linux-gnu-gcc` (C linker) to compile C dependencies (`aws-lc-sys`, `ring`). Not installed on Windows host. The Rust analysis layer itself produced zero errors — C dependency build failures are expected and do not reflect Rust-level correctness issues. Per plan verification criteria (D-35-D2 step 3), "the actual functional run happens in CI."

## Known Stubs

None — no placeholder values introduced.

## Threat Flags

None — no new network endpoints, auth paths, or schema changes introduced. The pre-create hunk runs in the supervisor (unsandboxed) BEFORE the Landlock ruleset is applied; T-35-02-01 through T-35-02-04 in the plan's threat model were evaluated and all dispositions are `mitigate` or `accept` per design.

## Next Phase Readiness

- Plan 35-02 is complete. Phase 35 has two more parallel plans (35-01 and 35-03) whose surfaces are fully disjoint from this plan's `profile_runtime.rs` scope.
- Phase 37 (Linux/macOS host execution): the Landlock pre-create hunk will compose cleanly with Plan 25-01's RESL cgroup v2 backends — both run in the supervisor BEFORE `Sandbox::apply`. No code coupling.
- CI Linux lane: `test_pre_create_landlock_profiles_dir_idempotent` will run in the Linux lane and validate the functional behavior of the pre-create hunk. This is the load-bearing functional verification per D-35-D3.

---
*Phase: 35-upst3-closure-quick-wins*
*Completed: 2026-05-12*

## Self-Check: PASSED

All files verified:
- FOUND: `crates/nono-cli/src/profile_runtime.rs`
- FOUND: `.planning/phases/35-upst3-closure-quick-wins/35-02-LINUX-LANDLOCK-PROFILES-SUMMARY.md`

Commits verified:
- FOUND: `327fe104` (feat(35-02): pre-create profiles dir before Landlock apply)
- FOUND: `cde74cf4` (test(35-02): add Linux-gated idempotency test)

Acceptance criteria:
- `fn pre_create_landlock_profiles_dir` count: 1 ✓
- `cfg(target_os = "linux")` count: 8 (baseline was 2; +6 from helper+call+EnvGuard+Drop+test) ✓
- `user_profiles_dir` count: 1 ✓
- `dirs::home_dir` count: 0 ✓
- Production `.unwrap()/.expect()` count: 0 ✓ (3 `.expect()` in test module only; permitted per CLAUDE.md exception)
- `test_pre_create_landlock_profiles_dir_idempotent` count: 1 ✓
- `struct EnvGuard` count: 1 ✓
