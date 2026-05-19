---
phase: 37
slug: linux-resl-backends-pkgs-auto-pull
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-19
---

# Phase 37 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Cargo built-in test runner (workspace standard) |
| **Config file** | None — workspace `Cargo.toml` defines test discovery; `[[test]]` sections per crate |
| **Quick run command** | `cargo test -p nono-cli --bin nono --release` (local-fast; ~30s on dev machine) |
| **Full suite command** | `cargo test --workspace --release` (Phase 37 close gate) |
| **Estimated runtime** | ~30s quick; ~10min full workspace; ~15min CI workflow `phase-37-linux-resl.yml` |

---

## Sampling Rate

- **After every task commit:** `cargo test -p nono-cli --bin nono --release` (workspace-local, Windows host fast)
- **After every plan wave:** `cargo test --workspace --release` + `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used`
- **Before `/gsd-verify-work`:** Full workspace green on dev host AND new `phase-37-linux-resl.yml` green on a fresh GitHub Actions run
- **Max feedback latency:** ~30s for quick samples; ~15min for full Linux runner cycle

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 37-01-01 | 01 | 1 | REQ-RESL-NIX-01 acc#3 | T-37-01 | Pre-fork detection on resource flags; v1 hosts fail-closed with typed variant carrying boot-flag hint | unit | `cargo test -p nono error::unsupported_kernel_feature_display_contains_cgroup_no_v1_hint --release` | ❌ Wave 0 | ⬜ pending |
| 37-01-02 | 01 | 1 | REQ-RESL-NIX-01/02/03 acc#3 | T-37-01 | Exhaustive FFI match: new variant → `ErrUnsupportedPlatform` (D-06 reuse, no ABI change) | unit | `cargo test -p nono-ffi map_error_unsupported_kernel_feature --release` | ❌ Wave 0 | ⬜ pending |
| 37-01-03 | 01 | 1 | REQ-RESL-NIX-01/02/03 acc#3 | T-37-01 | 4-of-5 cgroup detection sites (preserve site 4 path-traversal-guard as `UnsupportedPlatform`) emit new variant | integration (Linux CI only) | `cargo test -p nono-cli --test resl_nix_linux v1_host_unsupported_kernel_feature_emitted --release` | ❌ Wave 0 | ⬜ pending |
| 37-02-01 | 02 | 1 | REQ-PKGS-04 acc#4 | T-37-02 | `ProfileResolverArgs` struct with `no_auto_pull: bool`, `#[clap(flatten)]` into RunArgs + WrapArgs; env precedence: CLI > env > default | unit | `cargo test -p nono-cli cli::profile_resolver_args_env_precedence --release` | ❌ Wave 0 | ⬜ pending |
| 37-02-02 | 02 | 1 | REQ-PKGS-04 acc#4 | T-37-02 | `ResolveContext` threaded through `load_profile` (NOT thread-local, NOT global); auto-pull suppression honored | unit | `cargo test -p nono-cli profile::resolve_context_suppresses_auto_pull --release` | ❌ Wave 0 | ⬜ pending |
| 37-02-03 | 02 | 1 | REQ-PKGS-04 acc#4 | T-37-02 | DiagnosticFormatter footer indicates `--no-auto-pull` is set when `ProfileNotFound` fires under suppression | unit | `cargo test -p nono-cli output::diagnostic_footer_notes_no_auto_pull --release` | ❌ Wave 0 | ⬜ pending |
| 37-03-01 | 03 | 1 | REQ-RESL-NIX-01 acc#2 | — | `nono inspect` Limits-block emits `memory: 100M (cgroup v2 memory.max)` verbatim post-run on Linux | integration (Linux CI only) | `cargo test -p nono-cli --test resl_nix_linux inspect_memory_limits_block_locked_string --release` | ❌ Wave 0 | ⬜ pending |
| 37-03-02 | 03 | 1 | REQ-RESL-NIX-02 acc#2 | — | `nono inspect` emits `cpu_percent: 25 (cgroup v2 cpu.max 25000 100000)` verbatim | integration (Linux CI only) | `cargo test -p nono-cli --test resl_nix_linux inspect_cpu_percent_limits_block_locked_string --release` | ❌ Wave 0 | ⬜ pending |
| 37-03-03 | 03 | 1 | REQ-RESL-NIX-03 acc#2 | — | `nono inspect` emits `max_processes: 5 (cgroup v2 pids.max)` verbatim | integration (Linux CI only) | `cargo test -p nono-cli --test resl_nix_linux inspect_max_processes_limits_block_locked_string --release` | ❌ Wave 0 | ⬜ pending |
| 37-03-04 | 03 | 1 | REQ-RESL-NIX-01/02/03 acc#2 | — | Platform-aware emission via `#[cfg]` gates (per CLAUDE.md "explicit over implicit") — Windows/macOS path keeps current strings; Linux path emits LOCKED strings | unit | `cargo test -p nono-cli session_commands::limits_block_format_linux --release` (Linux only) + `cargo test -p nono-cli session_commands::limits_block_format_windows --release` | ❌ Wave 0 | ⬜ pending |
| 37-04-01 | 04 | 2 | REQ-RESL-NIX-01/02/03 acc#4 | T-37-03 | Workflow on `ubuntu-24.04`, always-on trigger (no path-filter), required-check on PRs to main | CI | `gh run list -w phase-37-linux-resl.yml --limit 1 --json conclusion -q '.[0].conclusion'` → `success` | ❌ Wave 0 | ⬜ pending |
| 37-04-02 | 04 | 2 | REQ-RESL-NIX-02 | T-37-03 | systemd-user-session via `loginctl enable-linger` + `machinectl shell <runner-user>@.host`; pre-step installs `/etc/systemd/system/user@.service.d/delegate.conf` with `Delegate=cpu cpuset io memory pids` BEFORE linger enable | CI | resl-nix job step: `cat /sys/fs/cgroup/user.slice/user-*.slice/user@*.service/cgroup.controllers \| grep -q cpu` (pre-test assertion) | ❌ Wave 0 | ⬜ pending |
| 37-04-03 | 04 | 2 | REQ-RESL-NIX-02 | — | New CPU-percent integration test exercises `cpu.max` path (currently no test covers REQ-RESL-NIX-02 functional behavior) | integration (Linux CI only) | `cargo test -p nono-cli --test resl_nix_linux linux_cpu_percent_throttles_yes_loop --release` | ❌ Wave 0 | ⬜ pending |
| 37-04-04 | 04 | 2 | REQ-RESL-NIX-03 | — | Verify N=5 case parameter matches REQ acceptance string (existing test may use N=10; adjust or add) | integration (Linux CI only) | `cargo test -p nono-cli --test resl_nix_linux linux_max_processes_5_fork_bomb_contained --release` | ✓ exists, may need parameter adjustment | ⬜ pending |
| 37-04-05 | 04 | 2 | REQ-RESL-NIX-01 | — | Existing memory OOM-kill test runs green on Linux runner | integration (Linux CI only) | `cargo test -p nono-cli --test resl_nix_linux linux_memory_limit_oom_kills_child --release` | ✓ exists (Phase 25-01) | ⬜ pending |
| 37-04-06 | 04 | 2 | Async-signal-safety regression | T-25-03 | No new `format!` calls in post-fork child arm | structural (compile-time + grep) | `cargo test -p nono-cli --test resl_nix_async_signal_safety --release` | ✓ exists (Phase 25-01) | ⬜ pending |
| 37-05-01 | 05 | 2 | REQ-PKGS-04 acc#1 | T-37-04 | Multi-endpoint mock registry (bundle.json + manifest.json + artifact) extends existing 50-LOC std-only TCP server; happy path: pull → verify → install → run | integration (Linux CI only) | `cargo test -p nono-cli --test auto_pull_e2e_linux auto_pull_happy_path --release` | ❌ Wave 0 | ⬜ pending |
| 37-05-02 | 05 | 2 | REQ-PKGS-04 acc#2 | T-37-04 | Unknown profile name fails closed with no implicit network call | integration (Linux CI only) | `cargo test -p nono-cli --test auto_pull_e2e_linux auto_pull_unknown_name_fails_closed --release` | ❌ Wave 0 | ⬜ pending |
| 37-05-03 | 05 | 2 | REQ-PKGS-04 acc#3 | T-37-04 / T-37-05 | Signature verification failure aborts before install; uses production Sigstore trust root + GitHub Actions OIDC issuer pin | integration (Linux CI only) | `cargo test -p nono-cli --test auto_pull_e2e_linux auto_pull_signature_failure_aborts --release` | ❌ Wave 0 | ⬜ pending |
| 37-05-04 | 05 | 2 | REQ-PKGS-04 acc#4 | T-37-02 | `--no-auto-pull` flag suppression returns existing `ProfileNotFound` error verbatim | integration (Linux CI only) | `cargo test -p nono-cli --test auto_pull_e2e_linux auto_pull_no_auto_pull_flag_falls_back_to_profile_not_found --release` | ❌ Wave 0 | ⬜ pending |
| 37-05-05 | 05 | 2 | REQ-PKGS-04 acc#1 | T-37-04 | Non-Policy pack-type rejection through auto-pull path (cheap ~30 LOC additional coverage per researcher Q3) | integration (Linux CI only) | `cargo test -p nono-cli --test auto_pull_e2e_linux auto_pull_rejects_non_policy_pack_type --release` | ❌ Wave 0 | ⬜ pending |
| 37-05-06 | 05 | 2 | REQ-PKGS-04 acc#3 | T-37-05 | CI-time keyless sign-blob via GitHub Actions OIDC token produces ephemeral signed fixture | CI | pkgs-auto-pull job step: `sigstore-sign sign-blob ... --identity-token $ACTIONS_ID_TOKEN_REQUEST_TOKEN` succeeds | ❌ Wave 0 | ⬜ pending |
| 37-06-01 | 06 | 3 | D-15 prerequisite | T-37-05 | TUF trust-root flake triage: Path (a) sigstore-rs version bump OR Path (b) NONO_TEST_HOME-based test-only trust root fallback | unit | `cargo test -p nono trust::bundle::tests::load_production_trusted_root_succeeds trust::bundle::tests::verify_bundle_with_invalid_digest --release` | ✓ exists; status RED at start, GREEN at close | ⬜ pending |
| 37-XX-CLIPPY | all | gate | Cross-target clippy invariant | — | Linux clippy from Windows host green (per CLAUDE.md mandate + memory feedback_clippy_cross_target) | static analysis | `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` | (manual; per-wave run) | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `crates/nono/src/error.rs` — add test `unsupported_kernel_feature_display_contains_cgroup_no_v1_hint` (REQ-RESL-NIX-01 acc#3, Plan 37-01)
- [ ] `bindings/c/src/lib.rs` — add test `map_error_unsupported_kernel_feature` (FFI exhaustive match, Plan 37-01)
- [ ] `crates/nono-cli/tests/auto_pull_e2e_linux.rs` — NEW file covering REQ-PKGS-04 acc#1–#4 + non-Policy pack rejection (Plan 37-05)
- [ ] `crates/nono-cli/tests/resl_nix_linux.rs` — add 4 new tests: inspect-string LOCKED-format (memory/cpu/pids), v1-host UnsupportedKernelFeature emission, CPU-percent throttling, max_processes=5 fork-bomb (Plan 37-03 + Plan 37-04)
- [ ] `.github/workflows/phase-37-linux-resl.yml` — NEW workflow with 2 jobs (resl-nix + pkgs-auto-pull), `ubuntu-24.04`, always-on trigger, required-check on PRs to main; pre-step installs `Delegate=cpu cpuset io memory pids` drop-in; `loginctl enable-linger` + `machinectl shell @<runner-user>@.host` (Plan 37-04)
- [ ] Framework install: none — Cargo test runner is workspace default
- [ ] No shared fixtures or `conftest.py` equivalent needed; tests use existing `require_cgroup_v2!` macro + EnvGuard RAII pattern

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Cross-target clippy from Windows host | CLAUDE.md mandate | Requires the `x86_64-unknown-linux-gnu` cross-toolchain installed on the dev host; CI does this automatically but executor verifies pre-PR | `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` |
| External binding-repo grep for `"Platform not supported"` Display-string drift | D-06 FFI reuse decision | Repos `nono-py` and `nono-ts` live outside this workspace; cannot grep from here | Manual: `cd ../nono-py && rg "Platform not supported"`; `cd ../nono-ts && rg "Platform not supported"`. Document in Plan 37-01 SUMMARY whether any consumer matches the old prefix. |
| GitHub Actions Linux runner verification | REQ-RESL-NIX-01/02/03 acc#4 + REQ-PKGS-04 acc#5 | Cannot be run on Windows dev host; only the runner exercises real cgroup-v2 + OIDC token issuance | Push branch → trigger workflow → confirm `phase-37-linux-resl.yml` green on the PR's checks tab |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references (5 missing files/tests above)
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s for per-task samples; < 15min for per-wave CI runner cycle
- [ ] `nyquist_compliant: true` set in frontmatter (set after planner produces PLAN.md files and all tasks verified to have either automated commands or explicit Wave 0 dependency references)

**Approval:** pending
