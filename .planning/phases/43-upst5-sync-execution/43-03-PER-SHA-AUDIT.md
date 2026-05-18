# Plan 43-03 — Per-SHA Pre-flight Audit

**Run:** 2026-05-18
**High-Risk Pre-flight per Plan 43-03 phase_context:** re-export surface diff on each of 8 commits to detect the cross-cluster trap that bit Plan 43-01.

## Pre-flight: re-export surface diff (cross-cluster dep detector)

```bash
for sha in 42601ed7 98c18f1f 18b03fa6 317c97b7 5098fc10 be23d6df a5985edd 64d9f283; do
  echo "=== $sha ==="
  git show $sha -- '**/mod.rs' '**/lib.rs' | grep -E '^[+-]pub (use|mod) '
done
```

**Result:** ZERO new `pub use` / `pub mod` lines added across all 8 Cluster 1 commits.

**Interpretation:** No cross-cluster re-export dependency. Cluster 1 is structurally isolated from the trust/signing symbol-introduction trap that caused Plan 43-01 BLOCKED. Cherry-pick chain is safe to proceed.

## Per-SHA audit table

| Chrono pos | SHA (8) | Files changed | Windows-touch (`*_windows.rs` \| `exec_strategy_windows` \| `nono-shell-broker/`) | `profile/mod.rs` touch | `override_deny`/`bypass_protection` occurrences | `Cargo.toml`/`workspace.toml` touch | Shape verdict |
|-----------:|---------|---------------|-----------------------------------------------------------------------------------|------------------------|-------------------------------------------------|-------------------------------------|---------------|
| 1 | `64d9f283` | 6 (app_runtime, cli, cli_bootstrap, package, package_cmd, registry_client) | 0 | 0 | 0 | 0 | Cluster-1-shape |
| 2 | `a5985edd` | 2 (cli, package_cmd) | 0 | 0 | 0 | 0 | Cluster-1-shape |
| 3 | `be23d6df` | 2 (package_cmd, registry_client) | 0 | 0 | 0 | 0 | Cluster-1-shape |
| 4 | `5098fc10` | 5 (main, pack_update_hint, sandbox_prepare + 2 docs/cli/*.mdx) | 0 | 0 | 0 | 0 | Cluster-1-shape (+ docs) |
| 5 | `317c97b7` | 2 (main, pack_update_hint) | 0 | 0 | 0 | 0 | Cluster-1-shape |
| 6 | `18b03fa6` | 1 (pack_update_hint) | 0 | 0 | 0 | 0 | Cluster-1-shape |
| 7 | `98c18f1f` | 4 (pack_update_hint + 3 docs/cli/*.mdx) | 0 | 0 | 0 | 0 | Cluster-1-shape (+ docs) |
| 8 | `42601ed7` | 1 (pack_update_hint) | 0 | 0 | 0 | 0 | Cluster-1-shape |

**Totals:** 0 Windows-file touches (D-43-E1 pre-check PASS); 0 `profile/mod.rs` touches (Phase 36-01b preservation PASS); 0 `override_deny` / `bypass_protection` occurrences (Phase 36-01c rename N/A); 0 `Cargo.toml` touches (no workspace-deps discipline needed per D-43-E5).

**Docs touches noted:** SHAs `5098fc10`, `98c18f1f` also touch `docs/cli/**/*.mdx` files (cross-platform user docs, NOT in plan `files_modified` list but cross-platform/portable; will land cleanly during cherry-pick).

## Cluster-isolation trap detector — verdict

**SAFE TO CHERRY-PICK.** No newly-added `pub use` / `pub mod` lines reference any symbol not introduced by the same cherry-pick. Cluster 1 has no implicit cross-cluster prerequisite commits (unlike Cluster 2 which depended on the unabsorbed trust/signing symbols). Phase 42 cluster-isolation assumption holds empirically for Cluster 1.
