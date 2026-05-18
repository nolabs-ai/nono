# Plan 43-03 — Cluster 1 cherry-pick chronological order

**Resolved:** 2026-05-18 via `for sha in 42601ed7 98c18f1f 18b03fa6 317c97b7 5098fc10 be23d6df a5985edd 64d9f283; do git log -1 --format='%aI %H %s' $sha; done | sort -k1`

Per Phase 40 Plan 40-01 DEV-1 lesson: cherry-picks applied in TRUE upstream chronological order (commit date), not Phase 42 ledger table order.

| Pos | Author date (ISO) | Full SHA | Subject |
|----:|-------------------|----------|---------|
| 1 | 2026-05-12T14:48:42+01:00 | `64d9f283cd3a95de6c6ff9423c39d4ed40fa73b4` | feat(package): add package pinning and outdated commands |
| 2 | 2026-05-12T14:56:21+01:00 | `a5985edd5d0e8b4111b1b01e2f4bf49908bf3aed` | feat(cli): implement `nono update` command |
| 3 | 2026-05-13T06:06:37+01:00 | `be23d6df47cdcd31c96d3e35abd9c98ca3cbf71e` | style(cli): improve formatting and simplify error handling |
| 4 | 2026-05-13T08:30:30+01:00 | `5098fc10e0942df7ee50e55fd45e8f181f02fa06` | feat(packs): add pinning, outdated, and clarify publishing versioning |
| 5 | 2026-05-13T08:45:34+01:00 | `317c97b70f2525a20ec501f0a2268eb9657715cb` | style(cli): adjust line breaks and module order |
| 6 | 2026-05-13T08:56:34+01:00 | `18b03fa625e6592beb99602278a83848d9e87ca0` | feat(pack_update_hint): refresh hints synchronously on first run |
| 7 | 2026-05-13T09:17:37+01:00 | `98c18f1f1ab5c60e7af506e7c65deb639972f065` | feat(pack-hints): document inline pack update hints |
| 8 | 2026-05-13T09:36:50+01:00 | `42601ed788008499fbd5aea6d1431a7701ccd081` | fix(pack-update-hint): treat unparsable installed as older in update check |

**Note on plan-frontmatter SHA `5098fc1c`:** the plan frontmatter listed `5098fc1c` but the canonical upstream commit is `5098fc10` (final char `0`, not `c`). Phase 42 ledger row showed 7-char abbrev `5098fc1` which matches. Using canonical 8-char `5098fc10` for the cherry-pick.

**Sequence Diff vs Phase 42 ledger order:** ledger ordered `42601ed → 98c18f1 → 18b03fa → 317c97b → 5098fc1 → be23d6d → a5985ed → 64d9f28` (ledger-table order). Chronological order is **reverse** of ledger order — the ledger appears to have ordered by ledger-row insertion, which is reverse-chronological. Cherry-picks proceed in chronological order per DEV-1 lesson.
