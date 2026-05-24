---
phase: 47-upst6-audit-v0-41-v0-43-drift-ingestion
plan: 01
purpose: D-47-A3 first-commit-of-Plan-47-01 upstream HEAD lock + UPST6 anchor tag verification
---

# Plan 47-01 Lock Notes — D-47-A3 upstream HEAD capture

This file records the post-fetch `upstream/main` sha and the UPST6 anchor-tag verification
captured as the FIRST act of Plan 47-01 per D-47-A3. The `upstream_head_at_audit` value below
is the source-of-truth for the DIVERGENCE-LEDGER.md frontmatter `upstream_head_at_audit` field
(Task 3). Plan 47-02 references this file to confirm the historical fetch state of UPST6
audit-open.

upstream_head_at_audit: 807fca38efc768c4e9856a0cb5c47d961b9287e5
v0.54.0_sha: 6b00932fe80a52b65f3718bb900878287640cc31
v0.55.0_sha: 35f9fea2b8239be1c49c98cd8be29fc6732d112d
v0.56.0_sha: b251c72fe5a4c7b1d1323307493db736be42c912
v0.57.0_sha: 10cec9845e14db24a50bf8e4a0fdda30c8395359
fetch_date: 2026-05-24

## Anchor tag verification (D-47-A3 / Task 1 acceptance criteria)

| Anchor tag | Expected prefix | Actual full sha | Verdict |
|------------|-----------------|-----------------|---------|
| v0.54.0    | `6b00932f`      | `6b00932fe80a52b65f3718bb900878287640cc31` | PASS |
| v0.55.0    | `35f9fea2`      | `35f9fea2b8239be1c49c98cd8be29fc6732d112d` | PASS |
| v0.56.0    | `b251c72f`      | `b251c72fe5a4c7b1d1323307493db736be42c912` | PASS |
| v0.57.0    | `10cec984`      | `10cec9845e14db24a50bf8e4a0fdda30c8395359` | PASS |

## Drift-tool reproducibility pin (D-47-A2 / D-47-E1)

`git log -1 --pretty=format:"%H" scripts/check-upstream-drift.sh` returns
`0834aa664fbaf4c5e41af5debece292992211559` — matches the D-47-A2 reproducibility pin.
`git log -1 --pretty=format:"%H" scripts/check-upstream-drift.ps1` returns the same commit
sha. Both scripts last touched at Phase 24 commit `0834aa66 feat(24-01): add categorization
+ by_category aggregate + grouped table format`. The pin convention is **commit sha** of the
most-recent change, not file content sha256 (Phase 33 / 39 / 42 inheritance).

## Post-v0.57.0 deferral context (D-47-A4 strictly-silent invariant)

upstream/main HEAD at post-fetch is `807fca38efc768c4e9856a0cb5c47d961b9287e5`, which is
ahead of the UPST6 upper bound `v0.57.0` (`10cec984`). The commits between `10cec984` and
`807fca38` are UPST7 scope per D-47-A4. Plan 47-01 is strictly silent on those commits;
the count is captured as a historical signal for the future UPST7 audit-walk.

Signed-off-by: Oscar Mack Jr <oscar.mack.jr@gmail.com>
