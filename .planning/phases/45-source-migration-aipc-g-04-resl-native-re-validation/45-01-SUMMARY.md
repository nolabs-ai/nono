---
phase: 45-source-migration-aipc-g-04-resl-native-re-validation
plan: 01
req: REQ-PORT-CLOSURE-08
commits: 7
status: complete
subsystem: bindings/c (nono-ffi)
tags:
  - edition-2024
  - ffi
  - no_mangle
  - divergence-ledger
  - phase-closure
dependency_graph:
  requires:
    - Phase 43 Plan 43-01b (MSRV + workspace dep centralization — workspace half of split)
  provides:
    - REQ-PORT-CLOSURE-08 (source-file half of split — closes Cluster 2 split disposition)
  affects:
    - bindings/c/include/nono.h (cbindgen-generated; verified byte-identical)
    - .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md (Cluster 2 disposition closed)
tech_stack:
  added: []
  patterns:
    - "#[unsafe(no_mangle)] — Edition 2024 explicit FFI export unsafe annotation"
key_files:
  created:
    - .planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-01-CLIPPY-CROSS-TARGET.md
  modified:
    - bindings/c/src/capability_set.rs (16 sites)
    - bindings/c/src/lib.rs (4 sites)
    - bindings/c/src/fs_capability.rs (7 sites)
    - bindings/c/src/sandbox.rs (3 sites)
    - bindings/c/src/state.rs (5 sites)
    - bindings/c/src/query.rs (4 sites)
    - .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md
decisions:
  - "REQ-PORT-CLOSURE-08: All 39 #[no_mangle] → #[unsafe(no_mangle)] substitutions committed across 6 FFI files (16+4+7+3+5+4 = 39); cbindgen header byte-identical; Cluster 2 split disposition closed"
  - "PARTIAL cross-target disposition accepted per 3-precedent pattern (Phase 41 + 43-01b + 44); live GH Actions Linux/macOS clippy lanes on Phase 45 head SHA are the decisive close signal"
metrics:
  duration: "~10 minutes (mechanical sweep)"
  completed: "2026-05-23"
  tasks_completed: 2
  files_modified: 8
---

# Phase 45 Plan 01: Edition 2024 Source Migration (bindings/c) Summary

**One-liner:** All 39 `#[no_mangle]` → `#[unsafe(no_mangle)]` FFI attribute sites in `bindings/c/src/` migrated per Rust Edition 2024 semantics; cbindgen header byte-identical; DIVERGENCE-LEDGER Cluster 2 flipped from `split` to `closed`.

## Closure Disposition

**REQ-PORT-CLOSURE-08 status: STRUCTURALLY-COMPLETE-PENDING-CROSS-TARGET-CI**

All structural criteria are satisfied on the Windows dev host:
- All 39 `#[no_mangle]` → `#[unsafe(no_mangle)]` substitutions committed
- cbindgen-generated `bindings/c/include/nono.h` is byte-identical
- Windows host `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` exits 0
- DIVERGENCE-LEDGER Cluster 2 disposition flipped from `split` to `closed`
- 7 commits landed with `chore(45-01):` subjects + `Replay-of: 79715aa5` + DCO sign-offs

The REQ remains at PARTIAL (not VERIFIED) pending live GH Actions Linux Clippy +
macOS Clippy lanes on the Phase 45 head SHA per the cross-target-verify-checklist.md
PARTIAL disposition protocol and the CLAUDE.md MUST/NEVER cross-target rule.

## Commit Manifest

| # | Hash | Subject |
|---|------|---------|
| 1 | `f640528a` | chore(45-01): bindings/c capability_set.rs Edition 2024 no_mangle (16 sites) |
| 2 | `84575492` | chore(45-01): bindings/c lib.rs Edition 2024 no_mangle (4 sites) |
| 3 | `e1645f78` | chore(45-01): bindings/c fs_capability.rs Edition 2024 no_mangle (7 sites) |
| 4 | `99e45379` | chore(45-01): bindings/c sandbox.rs Edition 2024 no_mangle (3 sites) |
| 5 | `f66fb767` | chore(45-01): bindings/c state.rs Edition 2024 no_mangle (5 sites) |
| 6 | `d21399e3` | chore(45-01): bindings/c query.rs Edition 2024 no_mangle (4 sites) |
| 7 | `f2ee8c51` | chore(45-01): DIVERGENCE-LEDGER Cluster 2 split → closed (79715aa5 close) |

**Total: 7 commits** (6 per-file sweeps + 1 DIVERGENCE-LEDGER amendment)

All commits carry:
- `chore(45-01):` subject prefix
- `Replay-of: 79715aa5 (Phase 43 Plan 43-01b DEC-3 split-disposition close)` body annotation
- `Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>` DCO trailer
- NO `Upstream-commit:` trailer block (correct per D-45-B1 — NOT a D-19 annotation)

## Verification

### Gate 1: cargo build --workspace --all-features
**PASS** — exits 0. No Edition 2024 non-mechanical surface revealed.

### Gate 2: cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used
**PASS** — exits 0. Windows host strict clippy clean with `#[unsafe(no_mangle)]` attributes.

### Gate 3: cargo test --workspace --all-features
**PASS** — 1082 tests pass, 1 pre-existing fail (`broker_launch_assigns_child_to_job_object`
requires `nono-shell-broker.exe` pre-built in `target/release/`; pre-dates Plan 45-01,
documented in Phase 41 CR-04 disposition, out-of-scope for this plan).

### Gate 4: cbindgen byte-identical gate
**PASS** — `cargo clean -p nono-ffi && cargo build -p nono-ffi --release` then
`git diff --exit-code bindings/c/include/nono.h` exits 0. Header is byte-identical.

### Gate 5: Zero remaining bare #[no_mangle] in bindings/c/src/
**PASS** — `grep -rc '#\[no_mangle\]' bindings/c/src/ | grep -v ':0$' | wc -l` = 0.
Per-file `#[unsafe(no_mangle)]` counts: 16 + 4 + 7 + 3 + 5 + 4 = 39.

### Gate 6: 7 chore(45-01): commits
**PASS** — `git log --pretty=format:'%s' main..HEAD | grep -c '^chore(45-01):'` = 7.
Order: capability_set.rs → lib.rs → fs_capability.rs → sandbox.rs → state.rs → query.rs → DIVERGENCE-LEDGER.

### Gate 7: DCO sign-offs and Replay-of annotations
**PASS** — `git log --pretty=format:'%b' main..HEAD | grep -c '^Signed-off-by: oscarmackjr-twg'` = 7.
`git log --pretty=format:'%b' main..HEAD | grep -c '^Replay-of: 79715aa5'` = 7.
`git log --pretty=format:'%b' main..HEAD | grep -c '^Upstream-commit:'` = 0 (correct).

### Gate 8: DIVERGENCE-LEDGER amendments
**PASS** — `grep -c '**Final disposition:** closed' .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md` = 1.
`grep -c '79715aa5' .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md` = 1.
`grep -c '**Disposition:** split' .planning/phases/42-upst5-audit/DIVERGENCE-LEDGER.md` = 1 (original preserved).

### Gate 9: CLIPPY-CROSS-TARGET.md artifact
**PASS** — file exists; contains 4 occurrences of `PARTIAL`; contains `live GH Actions`;
contains `cargo check` (Anti-pattern 3 acknowledgement). Disposition: PARTIAL.

### Gate 10: Windows-only-files invariant
**PASS** — `git diff --stat main..HEAD -- 'crates/**/*_windows.rs' 'crates/nono-cli/src/exec_strategy_windows/**' 'crates/nono-shell-broker/**'` is empty. Plan 45-01 does not touch Windows-only files.

## Cross-Target Posture

See `.planning/phases/45-source-migration-aipc-g-04-resl-native-re-validation/45-01-CLIPPY-CROSS-TARGET.md`
for the full cross-target verification protocol artifact.

**Summary:**
- Windows host clippy (`--all-targets`): PASS (exit 0)
- Linux cross-target (`x86_64-unknown-linux-gnu`): SKIPPED — `x86_64-linux-gnu-gcc` not found
- macOS cross-target (`x86_64-apple-darwin`): SKIPPED — `cc` for Darwin not found
- Disposition: PARTIAL (3rd time — matches Phase 41, 43-01b, 44 precedents)

**Phase 46 orchestrator hand-off:** The live GH Actions Linux Clippy + macOS Clippy lanes
on the Phase 45 head SHA close REQ-PORT-CLOSURE-08 at the cross-target level. The Phase 46
orchestrator records the verdict post-merge per the cross-target-verify-checklist.md
PARTIAL protocol.

## Anti-Pattern Audit

**Anti-pattern 2 — No `#[allow(...)]` introduced:**
Confirmed. `git diff main -- bindings/c/src/ | grep -c '#\[allow(clippy::unwrap_used)\]\|#\[allow(dead_code)\]'` = 0.
The substitution is purely literal — no new `unwrap`/`expect` callsites created, no dead code introduced.

**Anti-pattern 3 — `cargo check` NOT substituted for clippy:**
Confirmed. Windows host verification used `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (strict clippy with `unwrap_used` deny). Cross-target failures were due to missing C linker, not `cargo check` substitution.

## Deviations from Plan

None — plan executed exactly as written. The purely mechanical attribute substitution produced no surprises:
- cbindgen header remained byte-identical (D-45-B3 gate: PASS — no deviation)
- No new `unsafe extern "C"` block wrapping was required by the compiler
- No cfg-gated Unix drift was hidden by the substitution
- Cross-target clippy PARTIAL disposition matches the pre-documented 3-precedent pattern

## Known Stubs

None — this plan contains no data stubs, placeholder text, or unconnected components. The FFI exports are fully wired; the attribute substitution is complete and verified.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. The plan is a pure mechanical attribute substitution within an existing FFI boundary. The `T-45-01-01` threat (EoP from bare `#[no_mangle]`) is now mitigated as intended — all 39 FFI export sites explicitly declare their unsafe-ness at the attribute level.

## Self-Check: PASSED

- All 7 commit hashes verified in `git log`: `f640528a`, `84575492`, `e1645f78`, `99e45379`, `f66fb767`, `d21399e3`, `f2ee8c51`
- SUMMARY.md created at correct path
- CLIPPY-CROSS-TARGET.md created and committed
- DIVERGENCE-LEDGER.md amendment committed
- `git diff --exit-code bindings/c/include/nono.h` exits 0
- No modifications to STATE.md or ROADMAP.md (orchestrator handles those)
