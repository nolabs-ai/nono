## Plan 43-01b — Cluster 2 (split) workspace edits + MSRV bump (fork-authored)

**Cluster:** 2 (Rust edition 2024 + workspace deps centralization — split disposition per DIVERGENCE-LEDGER)
**Disposition:** split — workspace edits in 43-01b, source migration deferred to v2.6 / UPST6
**Upstream commits:** none cherry-picked in 43-01b (fork-authored). Predecessor Plan 43-01 attempted cherry-pick of `8b888a1c` — see `.planning/phases/43-upst5-sync-execution/43-01-EDITION-2024-FOUNDATION-SUMMARY.md` for BLOCKED disposition.
**Predecessor commits:** `fa0b826c` (BLOCKED SUMMARY on worktree branch) + `4afbaa67` (merge to main) + `e4a6bed7` (STATE.md blocker record).

**Files touched:** 6 Cargo.toml files + Cargo.lock + 4 source files (post-MSRV-bump clippy fix)

| Commit     | Files                                                                                | Change                                                                 |
|------------|--------------------------------------------------------------------------------------|------------------------------------------------------------------------|
| `b6aac925` | `Cargo.toml` + 5 per-crate `Cargo.toml`                                              | Workspace MSRV bump 1.77 → 1.95; centralize nix/landlock/getrandom deps; `[workspace.lints.clippy] unwrap_used = "deny"`; per-crate `[lints] workspace = true` |
| `f97d6561` | `Cargo.lock`                                                                         | Mechanical regeneration; nix 0.31.2 → 0.31.3 unification; lockfile format v3 → v4 (cargo 1.95 default) |
| `2603c7a6` | `crates/nono-cli/src/{audit_attestation,credential_runtime,session_commands_windows}.rs` + `crates/nono-cli/tests/audit_attestation.rs` | Rule 3 deviation: adopt `is_multiple_of()` for rust 1.95 `clippy::manual_is_multiple_of` lint (newly stabilized) — 10 sites across 4 files |

**Key decision:** Atomic fork-authored split of Cluster 2; workspace deps centralization + MSRV bump 1.77 → 1.95 + clippy-lints formalization. Edition bump (2021 → 2024) DEFERRED per Task 3 fallback path — `cargo check --workspace` failed under edition 2024 with 39 `#[no_mangle]` → `#[unsafe(no_mangle)]` source-migration errors in `bindings/c/src/`, exactly the deferred source-file migration scope. Edition stays at "2021"; deferral documented in SUMMARY DEC-3.

**Rule 3 deviation (commit `2603c7a6`):** the MSRV bump's second-order effect was new `clippy::manual_is_multiple_of` lint stabilization. 10 mechanical lint sites in 4 files (3 nono-cli src + 1 nono-cli test) auto-fixed to preserve "Zero green→red CI lane transitions vs baseline `13cc0628`" guarantee. One affected file is `session_commands_windows.rs` (fork-only Windows file); D-43-E1 invariant relaxed for this Rule 3 maintenance fix with explicit SUMMARY documentation.

**CI baseline diff:** to be filled in by orchestrator after CI runs. Expected zero `success → failure` transitions vs baseline `13cc0628`.

**Threat model close-out:** all `high` threats mitigated (T-43-01b-01 fork's version pin preserved; T-43-01b-02 D-43-E1 invariant honored for workspace edits commit; T-43-01b-03 MSRV-bump-surfaced lints caught + fixed by Rule 3 deviation; T-43-01b-04 edition fallback exercised). All `medium`/`low` threats mitigated or accepted with CI as detector.

**Acceptance criterion advanced:** REQ-UPST5-02 acceptance criterion #1 advanced for Cluster 2 (split workspace-edits portion). Source-migration portion explicitly tracked as v2.6/UPST6 follow-on in DIVERGENCE-LEDGER.
