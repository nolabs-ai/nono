---
status: issues_found
phase: 37
depth: standard
reviewer: gsd-code-reviewer
diff_base: d8670842ae5700df96db6f9d6a107889bf4b93ca
files_reviewed: 21
findings:
  critical: 0
  warning: 10
  info: 7
  total: 17
---

# Phase 37 Code Review

**Reviewed:** 2026-05-19
**Depth:** standard
**Diff base:** d8670842 (last commit before plan execution)

Phase 37 introduces the `UnsupportedKernelFeature` error variant + LOCKED cgroup-v2 hint, swaps 4-of-5 cgroup detection sites, adds the `--no-auto-pull` profile-resolver flag, introduces a Linux RESL CI workflow, and bumps `sigstore-verify` 0.6.5 → 0.7.0. No CRITICAL findings; 10 WARNING + 7 INFO findings, dominated by test thread-safety, brittle CI assumptions, and quality issues.

## CRITICAL findings

None identified.

## WARNING findings

### WR-01: doc-check awk parser silently skips multi-line `#[arg(...)]` attributes
**File:** `.github/scripts/check-cli-doc-flags.sh:24`
**Category:** quality / defense-in-depth defeated

The awk rule `/#\[arg\(/ && /long/ { attr = $0; next }` requires BOTH `#[arg(` and `long` to appear on the same line. When the `#[arg(...)]` attribute spans multiple lines (as `ProfileResolverArgs::no_auto_pull` does and as pre-existing flags like `SandboxArgs::allow` do), `attr` is never set and the field's `pub <name>:` line is skipped without emitting any flag name.

Empirically the script's parser pipeline emits neither `no-auto-pull` nor `allow`. The script only fails because `--dangerous-force-wfp-ready` (single-line `#[arg(...)]`) is hidden from the docs — a separate pre-existing miss.

Net effect: Phase 37 added `ProfileResolverArgs` to the struct list but the parser never observes the `no_auto_pull` field, so the doc-parity check passes vacuously for `--no-auto-pull`. Future flags with multi-line `#[arg(...)]` blocks will be silently exempted.

**Fix:** Accumulate multi-line attributes until the closing `)]` before evaluating.

### WR-02: LOCKED cgroup-v2 hint string duplicated across 5+ call sites
**File:** `crates/nono-cli/src/exec_strategy/supervisor_linux.rs:891,901,910,981,993,997` + `crates/nono/src/error.rs:421`
**Category:** quality / maintainability

The string `"cgroup v2 required; boot with systemd.unified_cgroup_hierarchy=1 or cgroup_no_v1=all"` is duplicated verbatim at every detection site. Comments call it "LOCKED" but no compile-time mechanism enforces synchronization.

**Fix:** Declare a single `const CGROUP_V2_HINT: &str = ...` inside `pub(super) mod cgroup`.

### WR-03: `auto_pull_e2e_linux.rs` env-var tests are not thread-safe
**File:** `crates/nono-cli/tests/auto_pull_e2e_linux.rs:29-61`
**Category:** test reliability / portability

The test file defines its own `EnvGuard` that calls `std::env::set_var`/`remove_var` without any cross-test mutex. The rest of the crate uses `crate::common::test_env::lock_env()` because Rust runs tests in parallel within the same process and env-var mutation races cause flaky failures (CLAUDE.md mandates this).

The workflow invokes `cargo test ... -- --test-threads=1` as belt-and-suspenders mitigation, but a developer running `cargo test --test auto_pull_e2e_linux` locally will hit races as soon as the test count grows past 1.

**Fix:** Add `mod common; use common::test_env::lock_env;` and take `let _lock = lock_env();` at the top of every test function before instantiating `EnvGuard`. Remove the `--test-threads=1` reliance.

### WR-04: `auto_pull_signature_failure_aborts` does not pin `XDG_CONFIG_HOME`
**File:** `crates/nono-cli/tests/auto_pull_e2e_linux.rs:391-465` (also sibling tests at 218, 280, 329, 492)
**Category:** test correctness / silent false-pass risk

Tests set `NONO_TEST_HOME` to a tempdir but the production `resolve_user_config_dir` checks `XDG_CONFIG_HOME` BEFORE falling through to `home_dir()`. If `XDG_CONFIG_HOME` is set on the CI runner, the install dir routes to `$XDG_CONFIG_HOME/nono/...`, not `$NONO_TEST_HOME/.config/nono/...`. The `!install_check.exists()` assertion would pass vacuously regardless of whether the production code actually aborted before install. The unit test `load_profile_with_context_suppresses_auto_pull_when_flag_set` gets this right.

**Fix:** In every test that sets `NONO_TEST_HOME`, also set `XDG_CONFIG_HOME` to the same tempdir.

### WR-05: `sigstore-verify` 0.7.0 introduces `verify_sct: bool` — security default not explicitly asserted
**File:** `crates/nono/Cargo.toml:48` + `VerificationPolicy::default()` call sites
**Category:** security-relevant assumption

The bump comment asserts `::default()` is unaffected — structurally true (no struct-literal in-tree) — but the SECURITY behavior of `::default()` now depends entirely on upstream's chosen default for `verify_sct`. If upstream's `Default` produces `verify_sct=false`, SCT validation is silently bypassed at every `VerificationPolicy::default()` callsite for offline-keyless verification.

**Fix:** Add a test that asserts `VerificationPolicy::default().verify_sct == true` so any future minor bump that flips the default forces an audit.

### WR-06: `cgroup_v2_available()` writable-check uses `permissions().readonly()` heuristic
**File:** `crates/nono-cli/tests/resl_nix_linux.rs:37-39`
**Category:** quality / brittle heuristic

`std::fs::Permissions::readonly()` on Unix is mode-bits only, not an actual "can the current process write" check. Inverted negation `!readonly()` is also slightly confusing.

**Fix:** Use `nix::unistd::access(path, AccessFlags::W_OK)` or just drop the gate entirely.

### WR-07: `linux_no_warnings_on_resource_flags` no longer guards Phase-16-stub-warning absence
**File:** `crates/nono-cli/tests/resl_nix_linux.rs:212-253`
**Category:** test coverage drift

Pre-Phase-37 the test would actually run on a cgroup-v1 host and assert no `"is not enforced on linux"` warning. Post-Phase-37 the command fails early with `UnsupportedKernelFeature` and the assertion passes vacuously without exercising the resource-limit code path.

**Fix:** Add `require_cgroup_v2!()` at the top, or split into positive/negative control tests.

### WR-08: CI workflow uses `${{ github.workspace }}` directly inside shell command
**File:** `.github/workflows/phase-37-linux-resl.yml:135`
**Category:** CI hygiene

GitHub-Actions best practice: never inject `${{ }}` directly into shell commands; pass via `env:`. Currently safe (runner-controlled path) but pattern is flagged by GitHub's own security guidance.

**Fix:** Use `env: WORKSPACE: ${{ github.workspace }}` then reference `"$WORKSPACE"` in the shell.

### WR-09: CI workflow `NONO_TRUST_OIDC_ISSUER` is set but no production code reads it
**File:** `.github/workflows/phase-37-linux-resl.yml:294`
**Category:** CI misleading / D-15 clause 2 not actually enforced

`grep -r NONO_TRUST_OIDC_ISSUER crates/` shows zero matches. The env var is currently inert. Documented as follow-up in the workflow comment, but the header asserts "REQ-PKGS-04 acceptance #4" coverage.

**Fix:** Implement the reader in `crates/nono/src/trust/signing.rs`, or add a `TODO(D-15-clause-2)` marker on the workflow line.

### WR-10: Hidden flags still required by doc-check script (pre-existing)
**File:** `.github/scripts/check-cli-doc-flags.sh:64-67` + `crates/nono-cli/src/cli.rs:1773` (`hide = true`)
**Category:** pre-existing parser blind spot

Doc-check exits non-zero on `--dangerous-force-wfp-ready` which is intentionally `hide = true`. Phase 37 didn't introduce it but didn't fix it either.

**Fix:** In the awk pipeline, skip fields whose accumulated `attr` contains `hide = true`.

## INFO findings

### IN-01: `EnvGuard::remove()` Drop may not restore on poisoned mutex
`crates/nono-cli/tests/auto_pull_e2e_linux.rs:44-51` — theoretical; tied to WR-03 fix.

### IN-02: Test spawns mock TCP server that is never contacted
`crates/nono-cli/tests/auto_pull_e2e_linux.rs:334-372` — listener thread blocks on `incoming()` until test teardown.

### IN-03: `format_bytes_short` duplicated between Unix and Windows mirrors
`crates/nono-cli/src/session_commands.rs:691-714` + `crates/nono-cli/src/session_commands_windows.rs:610-628` — semantically equivalent but will drift. Move to shared module.

### IN-04: `--no-auto-pull` help text does not mention `NONO_NO_AUTO_PULL` env var
`crates/nono-cli/src/cli.rs:1484-1496` — verify `--help` shows env-var hint; if not, prepend env name to help string.

### IN-05: `auto_pull_unknown_name_fails_closed` retry bound is fragile
`crates/nono-cli/tests/auto_pull_e2e_linux.rs:313-316` — `req_count <= 2` is hand-tuned; document expected request set or widen bound.

### IN-06: Cgroup-v2 detection "5 sites" enumeration jumps from site 3 to site 5a
`crates/nono-cli/src/exec_strategy/supervisor_linux.rs:888-1000` — internally consistent (site 4 is the kept-as-UnsupportedPlatform branch) but a reader may need a moment.

**Fix:** Add a one-line summary comment at the top of the `cgroup` module enumerating the 5 sites.

### IN-07: `diagnostic_formatter::format_error_footer` "set" grep-contract is unit-test-only
`crates/nono-cli/src/diagnostic_formatter.rs:25-41` — integration test at `auto_pull_e2e_linux.rs:362-365` greps for `--no-auto-pull` only. Minor.

## Highest-leverage fixes

1. **WR-01** (doc-check parser) — fixing the multi-line `#[arg(...)]` parse bug restores the documentation-parity gate for `--no-auto-pull` and ~30 other pre-existing multi-line flags. Single-change, high-coverage win.
2. **WR-05** (sigstore-verify SCT default) — adding a pin-test against `VerificationPolicy::default().verify_sct` locks the trust-posture assumption the Cargo.toml comment only claims.
3. **WR-03** (test thread-safety) — wiring `lock_env()` into `auto_pull_e2e_linux.rs` removes the `--test-threads=1` workflow dependency.

## Security posture

No security-critical defects identified in the swap of detection sites, the new flag, or the FFI mapping. Path-handling in `detect_from_str` correctly uses component-level checks per CLAUDE.md and the path-traversal guard is intentionally distinct (D-07).

WR-05 is the closest to security-relevant: the trust posture now depends implicitly on `sigstore-verify`'s upstream default for `verify_sct`. A pin-test would close that gap.
