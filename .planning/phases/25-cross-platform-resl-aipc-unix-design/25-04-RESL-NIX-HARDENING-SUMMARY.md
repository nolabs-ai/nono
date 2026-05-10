---
phase: 25-cross-platform-resl-aipc-unix-design
plan: 04
status: complete
created: 2026-05-10
completed: 2026-05-10
type: execute
tdd: true
risk: low
gap_closure: true
addresses: [WR-03, WR-05]
requirements: [REQ-RESL-NIX-01, REQ-RESL-NIX-03]
wave: 1
files_modified:
  - crates/nono-cli/src/exec_strategy/supervisor_linux.rs
  - crates/nono-cli/src/exec_strategy/supervisor_macos.rs
commits:
  - 7dcd9fe8: "fix(25-04): guard cgroup detect_from_str against /proc/self/cgroup path traversal (WR-03)"
  - f13ba84f: "fix(25-04): use idiomatic From<Errno> for io::Error in macOS install_pre_exec (WR-05)"
---

# Phase 25 Plan 04: RESL-NIX Hardening — Summary

## Outcome

Two code-review warnings from `25-REVIEW.md` closed across two atomic commits:

- **WR-03 (supervisor_linux.rs)** — `CgroupSession::detect_from_str` now rejects `/proc/self/cgroup` content that would construct a path escaping `/sys/fs/cgroup`. Three regression tests cover the two attack shapes (`0::/../../etc`, `0::/../../../proc/self`) plus the benign normal-path case.
- **WR-05 (supervisor_macos.rs)** — Both `setrlimit` `map_err` sites in `MacosResourceLimits::install_pre_exec` switched from `std::io::Error::from_raw_os_error(e as i32)` (relied on internal `#[repr(i32)]` of `nix::errno::Errno`) to the idiomatic `std::io::Error::from` (uses nix's public `From<Errno> for std::io::Error` impl). SAFETY doc comment rewritten to explain the change.

## Verification

All plan-level success criteria pass on this Windows host. Tests gated `#[cfg(all(test, target_os = "linux"))]` will execute on Linux CI; clippy and fmt pass on Windows where the target-gated module surface is exercised differently.

| # | Gate | Expected | Actual | Status |
|---|------|----------|--------|--------|
| 1 | `grep -c "starts_with.*sys/fs/cgroup"` in supervisor_linux.rs | ≥ 1 | 4 (1 production guard + 1 test scaffolding comment + 2 test assertions) | PASS |
| 2 | `cgroup_path_rejects_parent_dir_traversal` test name present | 1 | 1 | PASS |
| 3 | `cgroup_path_accepts_normal_path` test name present | 1 | 1 | PASS |
| 4 | `cgroup_path_rejects_encoded_traversal` test name present | 1 | 1 | PASS |
| 5 | `grep -c "from_raw_os_error"` in supervisor_macos.rs | 0 | 0 | PASS |
| 6 | `grep -c "map_err(std::io::Error::from)"` in supervisor_macos.rs | 2 | 2 | PASS |
| 7 | `grep -c 'From<Errno> for std::io::Error'` in supervisor_macos.rs | ≥ 1 | 2 (SAFETY doc references it twice) | PASS |
| 8 | `cargo check --package nono-cli` | exit 0 | exit 0 | PASS |
| 9 | `cargo clippy --package nono-cli -- -D warnings -D clippy::unwrap_used` | exit 0 | exit 0 | PASS |
| 10 | `cargo fmt --check --all` | exit 0 | exit 0 | PASS |

The three Linux-gated regression tests (`cgroup_path_rejects_parent_dir_traversal`, `cgroup_path_rejects_encoded_traversal`, `cgroup_path_accepts_normal_path`) compile on Windows hosts only inside the `#[cfg(all(test, target_os = "linux"))]` cgroup test module — they execute under `cargo test --package nono-cli` on Linux CI. The Windows host build was used to validate clippy and fmt cleanliness; Linux CI runs the test bodies.

## Key implementation note: `Path::starts_with` is necessary but NOT sufficient

The plan as written described the WR-03 fix as `abs_path.starts_with("/sys/fs/cgroup")` per CLAUDE.md § Path Handling — "use component comparison, not string operations". That is correct for cases like `/sys/fs/cgroupevil` (which `Path::starts_with` correctly rejects).

However, `Path::starts_with` does **not** normalize parent-directory components. The malicious input `0::/../../etc` produces `abs_path = "/sys/fs/cgroup/../../etc"`, whose components are `[/, sys, fs, cgroup, .., .., etc]`. That path **does** start with `/sys/fs/cgroup` at the component level — the four leading components match exactly — so `Path::starts_with` alone returns `true` and lets the traversal through.

The implemented guard combines two component-level checks (no string operations on either side):

```rust
use std::path::Component;
if !abs_path.starts_with("/sys/fs/cgroup")
    || abs_path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
{
    return Err(NonoError::UnsupportedPlatform(format!(
        "cgroup_v2: constructed cgroup path {abs_path:?} escapes /sys/fs/cgroup \
         (path traversal detected in /proc/self/cgroup content)"
    )));
}
```

This is recorded as a deviation below (Rule 1 — bug fix to the proposed implementation that, if applied verbatim, would not have caught the documented attack). The regression tests pin this stronger behavior so a future "simplification" cannot silently regress.

## Plan execution notes

- **TDD applied to Task 1.** Tests were written and added to the existing `#[cfg(all(test, target_os = "linux"))]` cgroup test module in the same file edit as the production guard. Because this Windows host cannot execute Linux-gated tests, the RED→GREEN cycle is verified by inspection of the regression test bodies + the production guard logic. The `cgroup_path_rejects_parent_dir_traversal` test specifically asserts `NonoError::UnsupportedPlatform(msg) where msg.contains("path traversal") || msg.contains("escapes")` — both substrings appear in the production error message, so the test will pass on Linux CI.
- **Task 2 was a straight code transformation** plus a doc-comment rewrite. No test changes required — existing macOS tests (`new_rejects_cpu_percent`, `new_with_all_none_is_ok`) already cover the call sites; the public behavior is unchanged.
- **Both commits include DCO `Signed-off-by` lines** per CLAUDE.md § Coding Standards.
- **No edits to `exec_strategy.rs`** — WR-02 (setrlimit fail-closed in the supervised child branch) and WR-04 (`getpgid` watchdog match) are owned by Plan 25-03 per scope-split. This plan touched only the two `supervisor_*.rs` files as specified by `files_modified` frontmatter.

## Deviations from plan

### Auto-fixed Issues

**1. [Rule 1 — Bug] Strengthened the WR-03 guard to also reject `Component::ParentDir`**
- **Found during:** Task 1 verification, after writing the initial guard from the plan's literal action text.
- **Issue:** The plan's proposed fix was `if !abs_path.starts_with("/sys/fs/cgroup") { return Err(...); }`. By itself, `Path::starts_with` is component-level but does not normalize `..` — so `/sys/fs/cgroup/../../etc` (the exact attack path the plan's `behavior` clause cites: `detect_from_str("0::/../../etc")` must return `Err(...)` containing `"path traversal"`) would pass `Path::starts_with("/sys/fs/cgroup")` and the test would fail.
- **Fix:** Combined `Path::starts_with` with `components().any(|c| matches!(c, Component::ParentDir))` so both the directory-prefix invariant and the no-`..` invariant are enforced. Both checks remain component-level (no string `starts_with`); the additional `Component::ParentDir` scan operates on the iterator returned by `Path::components()`, not on string slices. The error message is preserved (`"path traversal detected in /proc/self/cgroup content"`).
- **Files modified:** `crates/nono-cli/src/exec_strategy/supervisor_linux.rs`
- **Commit:** `7dcd9fe8`
- **Result:** All three regression tests defined in the plan's `behavior` clause are satisfiable by the production guard.

### Other notes

- The plan's verification step `grep -c 'From<Errno> for std::io::Error'` returned a count of 2 on the final file (vs the spec's `>= 1`) because the SAFETY doc comment references the impl in both the prose explanation and the rationale paragraph. This exceeds the criterion (≥ 1) and is documentation, not duplication of behavior.

## Cross-references

- Plan: [`25-04-RESL-NIX-HARDENING-PLAN.md`](./25-04-RESL-NIX-HARDENING-PLAN.md)
- Source review: [`25-REVIEW.md`](./25-REVIEW.md) — WR-03 (lines 159–185) and WR-05 (lines 211–227)
- Companion gap-closure: [`25-03-RESL-NIX-FIXES-PLAN.md`](./25-03-RESL-NIX-FIXES-PLAN.md) (CR-01, CR-02, WR-02, WR-04)
- Phase context: [`25-CONTEXT.md`](./25-CONTEXT.md)
- Phase verification: [`25-VERIFICATION.md`](./25-VERIFICATION.md)
- Project rule: `CLAUDE.md` § Path Handling — "Always use path component comparison, not string operations. String `starts_with()` on paths is a vulnerability."

## Threat-model coverage

The plan's `<threat_model>` lists two STRIDE entries; both are now mitigated as specified:

| Threat ID | Category | Component | Disposition (planned) | Status (after this plan) |
|-----------|----------|-----------|------------------------|--------------------------|
| T-25-04-01 | Elevation of Privilege | `CgroupSession::detect_from_str` path construction | mitigate via `Path::starts_with("/sys/fs/cgroup")` | **Mitigated** — `Path::starts_with` + `Component::ParentDir` scan; three regression tests pin the behavior |
| T-25-04-02 | Tampering | nix `Errno` internal repr change | mitigate by switching to `From<Errno> for std::io::Error` | **Mitigated** — both `map_err` sites in `install_pre_exec` use the documented public conversion API |

## Self-Check: PASSED

- File `crates/nono-cli/src/exec_strategy/supervisor_linux.rs`: FOUND (modified, +76 lines)
- File `crates/nono-cli/src/exec_strategy/supervisor_macos.rs`: FOUND (modified, +11/-3 lines)
- Commit `7dcd9fe8`: FOUND on `worktree-agent-add1cd71d432acafb`
- Commit `f13ba84f`: FOUND on `worktree-agent-add1cd71d432acafb`
- SUMMARY.md will be committed via the metadata commit step that follows.
