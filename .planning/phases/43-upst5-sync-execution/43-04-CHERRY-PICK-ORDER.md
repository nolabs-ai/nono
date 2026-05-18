# Plan 43-04 Cherry-Pick Order

Sorted by upstream commit date (Task 1 step 3). Apply in this order.

| Position | Upstream SHA | Date (ISO-8601) | Subject |
|---|---|---|---|
| 1 | `803c6947` | 2026-05-11T22:31:59Z | chore(deps): bump nix from 0.31.2 to 0.31.3 |
| 2 | `6b00932f` | 2026-05-13T09:52:48+01:00 | chore: release v0.54.0 |

**Execution:** Task 2 cherry-picks 803c6947 first (straight cherry-pick — but see PRE-CHERRY-PICK-AUDIT.md for the empty-diff expectation given Plan 43-01b already promoted nix to workspace-level at 0.31.3). Task 3 cherry-picks 6b00932f second (release-ride with revert of Cargo.toml/Cargo.lock/per-crate version hunks per D-43-E10).
