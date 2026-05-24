---
phase: 47-upst6-audit-v0-41-v0-43-drift-ingestion
plan: 02
purpose: D-47-A3 first-commit-of-Plan-47-02 upstream HEAD lock + v0.41–v0.43 backfill anchor-tag verification + cross-ledger correlation to Plan 47-01 lock
---

# Plan 47-02 Lock Notes — D-47-A3 upstream HEAD capture (backfill range)

This file records the post-fetch `upstream/main` sha and the v0.41.0..v0.43.0
backfill-range anchor-tag verification captured as the FIRST act of Plan 47-02
per D-47-A3. The `upstream_head_at_audit` value below is the source-of-truth
for the `DIVERGENCE-LEDGER-v041-v043-backfill.md` frontmatter
`upstream_head_at_audit` field (Task 2). The HEAD-anchor is informational for
this plan because the backfill range is fully historical (D-47-A3 schema
uniformity); the field is captured for schema parity with the Plan 47-01
UPST6 ledger.

upstream_head_at_audit: 807fca38efc768c4e9856a0cb5c47d961b9287e5
v0.41.0_sha: 073620e952bd7eddbcd0adb10d6519a0d36904fb
v0.43.0_sha: 30c0f76e7be31dd2bcf6e7b3c1ac36347e97fcc5
fetch_date: 2026-05-24
plan_47_01_head_at_audit: 807fca38efc768c4e9856a0cb5c47d961b9287e5

## Cross-ledger correlation (Plan 47-01 → Plan 47-02)

The `upstream_head_at_audit` value is IDENTICAL to Plan 47-01's lock
(`807fca38efc768c4e9856a0cb5c47d961b9287e5`) — Plan 47-02 ran immediately
after Plan 47-01 close on the same dev-host fetch (no intervening
`git fetch upstream --tags` between Plan 47-01 SUMMARY commit
`177232ca` and the Plan 47-02 first commit, so post-fetch HEAD is stable).
This is the normal sequential-plan-ordering path per D-47-B3; an
identical HEAD value across both Plan 47-01 and Plan 47-02 lock-notes
preserves cross-ledger reproducibility.

## Anchor tag verification (D-47-A3 / Task 1 acceptance criteria)

| Anchor tag | Expected prefix | Actual full sha | Verdict |
|------------|-----------------|-----------------|---------|
| v0.41.0    | `073620e9`      | `073620e952bd7eddbcd0adb10d6519a0d36904fb` | PASS |
| v0.43.0    | `30c0f76e`      | `30c0f76e7be31dd2bcf6e7b3c1ac36347e97fcc5` | PASS |

## Drift-tool reproducibility pin (D-47-A2 / D-47-E1)

`git log -1 --pretty=format:"%H" scripts/check-upstream-drift.sh` returns
`0834aa664fbaf4c5e41af5debece292992211559` — matches the D-47-A2
reproducibility pin invariant (unchanged since Phase 24 ship 2026-04-29
through Phase 33 + 39 + 42 + 47). `git log -1 --pretty=format:"%H"
scripts/check-upstream-drift.ps1` returns the same commit sha. The pin
convention is **commit sha** of the most-recent change, not file content
sha256 (Phase 33 / 39 / 42 / 47 Plan 47-01 inheritance).

## Backfill drift-tool invocation result preview (D-47-B4 step 1)

Locked invocation (D-47-A2):
`make check-upstream-drift ARGS="--from v0.41.0 --to v0.43.0 --format json"`

Dispatched on Windows host via `bash scripts/check-upstream-drift.sh
--from v0.41.0 --to v0.43.0 --format json` per Phase 33 + 39 + 42 + 47 Plan
47-01 Rule 3 deviation precedent since `make` is not on PATH. Same shell
command, same JSON output, same drift-tool sha — reproducibility preserved.

JSON output redirected to `ci-logs-local/drift/20260524T025014Z-v041-v043.json`
per D-47-E1 / D-33-A2 inherited (`ci-logs-local/` is in `.gitignore`;
`git check-ignore -v` confirms the path is ignored). NOT committed.

`total_unique_commits: 11` (post-D-11 fork-shared filter; CONTEXT § Drift
signal preview estimate was ~19 raw / unfiltered; actual post-filter count
on the v0.41.0..v0.43.0 backfill range is 11). This is the row-count target
the ledger commit-row tables MUST cover (D-47-B4 step 2 exact coverage zero
gap; >= 11 sum across all cluster tables).

`by_category` distribution: `profile=2, policy=0, package=0, proxy=1,
audit=0, other=11` (overlap on multi-category commits — `other` is the
catch-all and aggregates with category-specific labels per Phase 24 D-05
multi-label semantics).

## Historical absorption context (D-47-C1 + D-47-C2 + D-47-C3 absorbed-via reconstruction)

The v0.41.0..v0.43.0 range was the explicit absorption scope for Phase 34
UPST3 (v2.3 milestone; Plans 34-00..34-10; closed 2026-05-12 per commit
`01abbdf4`). Per Phase 34 D-34-A3 + `34-PHASE-OUTCOMES.md` (now superseded
by Phase 34 close artifacts), 12 cluster dispositions resolved:
- 8 `will-sync` clusters (C2, C4, C5, C7, C8, C9, C10, C12) absorbed via
  Plans 34-00..34-08 with verbatim D-19 trailers.
- 2 `fork-preserve` clusters (C6 packs, C11 proxy-TLS).
- 2 `won't-sync` clusters (C1 PTY attach/detach, C3 Unix-socket
  capability).

The backfill ledger's `absorbed-via:` column (D-47-C3) reconstructs the
per-commit attribution against this historical record. **Subject-line +
D-19 trailer match against fork main is the load-bearing detection
methodology** (D-47-C2). CONTEXT § Drift signal preview's "only 11 unique
`Upstream-commit:` trailers exist in fork main" framing is dated — fork
main now carries D-19 trailers on every Phase 34 + 40 + 43 cherry-pick;
trailer match yields unambiguous attribution for 7/11 backfill commits.
The remaining 4 commits (1 Cargo.toml version bump for v0.42.0; 3
Unix-socket capability commits) are `intentionally-skipped` per Phase 34
C3 won't-sync disposition + Phase 34 D-34-B2 Cargo.toml rejection
posture. No `unmatched` candidates for Phase 48 absorption are expected
on this range.

Signed-off-by: Oscar Mack Jr <oscar.mack.jr@gmail.com>
