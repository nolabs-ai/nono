---
status: gaps_found
phase: 25-cross-platform-resl-aipc-unix-design
source: [25-VERIFICATION.md]
started: 2026-05-10T17:50:00Z
updated: 2026-05-10T22:00:00Z
---

## Current Test

[all 6 tests blocked pending upstream-parity sync — see Gap G-25-DRIFT-01]

## Tests

### 1. Linux OOM kill via cgroup v2 memory.max
expected: `nono run --memory 256m -- bash -c 'tail -c 1G </dev/urandom'` exits non-zero (OOM-killed by cgroup). Optional: `nono inspect <id>` shows `memory_kill: true` — note this field was scoped as optional follow-up in the plan.
result: blocked
blocked_by: upstream-drift
reason: "`--memory` flag deprecated/renamed in upstream nono v0.52. Test command no longer matches upstream surface; must be re-validated after upstream-parity sync (see Gap G-25-DRIFT-01)."

### 2. Linux fork-bomb mitigation via cgroup v2 pids.max
expected: `nono run --max-processes 10 -- bash -c 'for i in {1..20}; do sleep 60 & done; wait'` exits non-zero (fork failure after 10 processes).
result: blocked
blocked_by: upstream-drift
reason: "`--max-processes` flag deprecated/renamed in upstream nono v0.52. Test command no longer matches upstream surface; must be re-validated after upstream-parity sync (see Gap G-25-DRIFT-01)."

### 3. Linux supervisor watchdog timeout
expected: `nono run --timeout 5s -- sleep 60` exits non-zero within 3-10s (watchdog fires via `cgroup.kill`).
result: blocked
blocked_by: upstream-drift
reason: "`--timeout` flag deprecated/renamed in upstream nono v0.52. Test command no longer matches upstream surface; must be re-validated after upstream-parity sync (see Gap G-25-DRIFT-01)."

### 4. Linux no-warning assertion
expected: Running any of the above commands emits zero stderr lines containing `is not enforced on linux` (the Unix-side stub warnings are gone).
result: blocked
blocked_by: upstream-drift
reason: "Depends on tests 1-3 commands which use deprecated/renamed flags. Re-validate after upstream-parity sync (see Gap G-25-DRIFT-01)."

### 5. macOS RLIMIT_AS enforcement
expected: `nono run --memory 256m -- bash -c '<large alloc>'` exits non-zero (RLIMIT_AS aborts the child during mmap).
result: blocked
blocked_by: upstream-drift
reason: "`--memory` flag deprecated/renamed in upstream nono v0.52. Test command no longer matches upstream surface; must be re-validated after upstream-parity sync (see Gap G-25-DRIFT-01)."

### 6. macOS --cpu-percent clap rejection
expected: `nono run --cpu-percent 50 -- ls` exits non-zero at parse time with error message indicating cpu-percent is not supported on macOS; no child spawned.
result: blocked
blocked_by: upstream-drift
reason: "`--cpu-percent` flag deprecated/renamed in upstream nono v0.52. Test command no longer matches upstream surface; must be re-validated after upstream-parity sync (see Gap G-25-DRIFT-01)."

## Summary

total: 6
passed: 0
issues: 0
pending: 0
skipped: 0
blocked: 6

## Gaps

### G-25-DRIFT-01 — Upstream parity drift on all 4 RESL flag names (v0.52)
severity: warning
status: closed: no-divergence
discovered: 2026-05-10
discovered_in: 25-HUMAN-UAT (test 1 attempt)

**What:** All four RESL flags shipped by Phase 25 (`--memory`, `--cpu-percent`, `--max-processes`, `--timeout`) have been deprecated or renamed in upstream nono v0.52. This branch's last upstream sync was Phase 22 UPST2 (v0.38–v0.40), so v0.41–v0.52 has accumulated divergence on the RESL flag surface specifically.

**Where:** `crates/nono-cli/src/cli.rs` — flag definitions at lines ~1966 (`--memory`), the `--cpu-percent` parser around line 83, plus `--max-processes` and `--timeout` declarations elsewhere in the same file. Phase 25 plans (25-01 through 25-06) all reference these flag names verbatim. The Windows-side enforcement from v2.1 Phase 16 inherits the same names.

**Impact:**
- Phase 25's source-level closure is INTACT (Linux cgroup v2 + macOS setrlimit backends correctly enforce against the flag values they receive — that's a backend correctness property independent of flag naming).
- The user-facing CLI surface diverges from upstream v0.52 — anyone following upstream nono docs will hit "unknown flag" errors against this build.
- All 6 HUMAN-UAT tests cannot be re-validated until either (a) upstream sync brings flag names current, or (b) the tests are rewritten with whatever-this-branch-calls-them and a separate cross-fork divergence is documented.

**Why not caught earlier:** Phase 22 UPST2 was scoped as v0.38–v0.40 only. The DRIFT-01/DRIFT-02 tooling from Phase 24 (`check-upstream-drift` + GSD quick-task template) is the right machinery for this — it just hasn't been run against v0.52 yet.

**Recommended follow-up:**
- New phase or quick-task: **UPST3 — Upstream v0.41–v0.52 Parity Sync** (RESL flag rename surface specifically; may surface other drift areas worth folding in).
- Use the Phase 24 DRIFT tooling (`check-upstream-drift` + 260428-rsu-style quick-task template) as the entry point.
- Do NOT block Phase 25 milestone close on this — Phase 25's source-level deliverables are correct against the v0.40 baseline. The drift is a separate concern.

**Cross-references:**
- Phase 22 UPST2 SUMMARY (last upstream sync — through v0.40)
- Phase 24 DRIFT-01 (`check-upstream-drift` tooling) + DRIFT-02 (quick-task template)
- 260428-rsu deferred runbook (upstream-stack rebase pattern)

**Update (Phase 33, 2026-05-11):**

1. **Drift audit summary:** The Wave 1 drift audit walked upstream v0.40.1..v0.52.0 (97 commits across 12 themed clusters) for the 4 RESL-flag-rename keywords originally suspected (`--memory`, `--cpu-percent`, `--max-processes`, `--timeout`) and found zero matches. The renames G-25-DRIFT-01 anticipated do not exist in upstream HEAD `54f7c32a` as of 2026-05-11. See [`DIVERGENCE-LEDGER.md`](../33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md) for the full audit data.
2. **Parity-strategy ADR decision:** The strategic ADR landed at [`docs/architecture/upstream-parity-strategy.md`](../../../docs/architecture/upstream-parity-strategy.md) picked option A: `continue` bidirectional parity. Implication for this gap: with the rename hypothesis disproved, there is nothing for UPST3 (Phase 34) to sync for G-25-DRIFT-01 specifically. The gap can remain `open` as a documented audit finding (premise empirically disproved) until a future audit surfaces actual upstream RESL drift, OR closed administratively in a separate decision.
3. **Closure handoff:** Gap stays `status: open` until a future audit cycle (UPST3-sync or a later UPST4+ cycle) either surfaces actual upstream RESL drift or formally re-classifies this entry. **Phase 33 does NOT close G-25-DRIFT-01** — the audit + decision artifacts ship without altering the gap's status per SPEC.md § Out of scope. Closure decision is deferred (closure rationale would be "premise disproved; no upstream renames to sync" rather than "work completed").
4. **Audit-walk note:** Audit surfaced ZERO RESL-flag-rename commits — fewer than the 4 originally suspected from Phase 25 HUMAN-UAT. No cluster in DIVERGENCE-LEDGER.md covers this surface. The RESL flag rename hypothesis is empirically disproved against `upstream/main` HEAD `54f7c32a` at 2026-05-11.

**Closure (Phase 34, 2026-05-11):**

This gap is hereby closed with disposition `no-divergence`. The Phase 33 drift audit walked upstream `v0.40.1..v0.52.0` (97 non-merge commits across 12 themed clusters) for the four RESL flag rename keywords originally suspected at Phase 25 HUMAN-UAT time (`--memory`, `--cpu-percent`, `--max-processes`, `--timeout`) and surfaced **zero matches**. The renames G-25-DRIFT-01 anticipated do not exist in upstream HEAD `54f7c32a` as of 2026-05-11. Upstream v0.52.0 still ships all four flags under their original Phase 25 names; the fork's RESL surface is **not** diverged from upstream. The Phase 25 HUMAN-UAT premise was speculative-reading-of-churn, not an audit-grounded finding.

Implication: there is no upstream RESL rename work for Phase 34 UPST3-sync to absorb. The six blocked HUMAN-UAT tests (Tests 1-6) can be re-validated on a Linux/macOS host as soon as Plan 25-01 (queued for v2.3 close) executes — the flag names listed in 25-HUMAN-UAT.md Tests 1-6 match upstream verbatim.

Authoritative source: [`DIVERGENCE-LEDGER.md`](../33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md) § Headline (CRITICAL audit finding paragraph) + § Cluster: Env deny_vars + macOS learn diagnostics + nono learn deprecation § Audit finding paragraph. Cross-references: [Phase 33 33-CONTEXT.md](../33-windows-parity-upstream-0-52-divergence/33-CONTEXT.md) D-33-D2; [Phase 34 34-CONTEXT.md](../34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md) D-34-C1.
