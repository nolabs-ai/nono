---
slug: phase-37-post-fix-runtime
status: root_cause_found
trigger: "After landing the BUG-1 + BUG-2 compile fixes from quick-task 260523-kzd (commit a8d771d5), the push-triggered Phase 37 RESL workflow run 26341685999 still fails — but at NEW layers further into both jobs. PKGS-04: 3 of 6 auto_pull e2e tests fail at runtime assertion (auto_pull_happy_path_mock, auto_pull_rejects_non_policy_pack_type, auto_pull_signature_failure_aborts). RESL-NIX: cross-target clippy now hits `unwrap_err()` lint at crates/nono-cli/src/profile_cmd.rs:3836 under `-D clippy::unwrap_used`. Both failures were structurally hidden behind the original 2 compile errors. Diagnose-only — operator wants to plan the fix as a follow-up quick-task."
goal: find_root_cause_only
created: 2026-05-23
updated: 2026-05-23
phase: 46
related_phases: [37]
related_requirements: [REQ-CI-FU-01]
related_sessions: [phase-37-resl-failure]
related_quick_tasks: [260523-kzd, 260523-moe]
---

## REVISED DIAGNOSIS (quick-260523-moe pre-flight verification)

**The original "BUG-A: URL path mismatch + `@latest` suffix" hypothesis below is INCORRECT.** Verifying the production code path before fixing surfaced that `@latest` in the panic message is just the error-message format from `crates/nono-cli/src/registry_client.rs:124-131` (`"registry returned HTTP {} for {}/{}@{}"`) — a friendly identifier, **not the URL**. The actual URL the production client requests is `/api/v1/packages/{ns}/{name}/versions/{version}/pull` (`registry_client.rs:60-63`).

The true BUG-A root cause is a **protocol mismatch between the test mock and production code**:

| Side | Protocol |
|------|----------|
| Production (`run_pull` → `fetch_pull_response` → `download_and_verify_artifacts`) | REST: `GET /api/v1/packages/{ns}/{name}/versions/{ver}/pull` → `PullResponse{bundle_url, artifacts[{download_url, sha256_digest}]}`; then `GET {bundle_url}` (sigstore bundle) + per-artifact `GET {download_url}`, verifying each digest is a subject in the sigstore bundle |
| Test mock (`auto_pull_e2e_linux.rs`) | Static-file layout: `/bundle.json` (custom "packs index"), `/mock-ns/mock-pack/manifest.json` (PackageManifest), `/mock-ns/mock-pack/artifact.tar.gz`, `/mock-ns/mock-pack/artifact.tar.gz.sigstore.json` |

The production binary's first request — `/api/v1/packages/mock-ns/mock-pack/versions/latest/pull` — doesn't match any mock route, so the mock returns the default 404 and the binary fails with `Registry error: registry returned HTTP 404 for mock-ns/mock-pack@latest`. The `req_count=1` in the panic message is the smoking gun: exactly one request reached the mock before failure.

Deeper consequence: the CI fixture-pack step only signs `artifact.tar.gz`, so the sigstore bundle's subjects contain only that one digest. Production expects EVERY `pull.artifacts[].sha256_digest` to be a subject — meaning a faithful test would also have to restructure the CI fixture pack so `package.json` is a separately-signed top-level artifact (or sign over the artifact set differently). The 3 failing tests were authored against a phantom registry protocol that production never implemented; `auto_pull_unknown_name_fails_closed` passes only because the mock returns 404 to everything (matching the production "fail-closed" expectation).

**BUG-B diagnosis below remains correct.** The clippy violation is exactly as documented — the test module at `profile_cmd.rs:3363` is missing the `#[allow(clippy::unwrap_used)]` annotation that every other test module with `unwrap_err()` calls carries.

### Scope decision (operator, 2026-05-23 via 260523-moe AskUserQuestion)

- **Fix BUG-B only** — add `#[allow(clippy::unwrap_used)]` to `profile_cmd.rs` test module
- **`#[ignore]` the 3 broken tests** with a `// TODO` pointing at the protocol-rewrite follow-up — unblocks the Phase 37 RESL workflow today
- **Defer** the real test rewrite (mock→production protocol) to a separately-planned follow-up phase. Tracking REQ-CI-FU-01 already covers this surface; no new requirement needed.

---
## Original hypotheses (kept for audit trail — BUG-A is superseded by the revised diagnosis above)

# Debug: Phase 37 RESL post-fix runtime failures

## Symptoms

### Expected behavior
After the 260523-kzd compile fixes (BUG-1 sign-fixture workspace member + BUG-2 std::result qualification on 3 supervisor_linux.rs test fns) land on `origin/main`, the push-triggered Phase 37 RESL workflow should reach its integration test phase and produce two green job conclusions. Per 37-VERIFICATION.md human_verification block: `auto_pull_happy_path_mock`, `auto_pull_unknown_name_fails_closed`, `auto_pull_no_auto_pull_flag_falls_back_to_profile_not_found`, `auto_pull_signature_failure_aborts`, `auto_pull_rejects_non_policy_pack_type` all pass; cross-target Linux clippy lane exits 0.

### Actual behavior
Run 26341685999 (push of SHA a8d771d5 to main, dispatched 2026-05-23T19:36:35Z) BOTH jobs now compile successfully (BUG-1 + BUG-2 resolved — verified by the build steps completing without error) but FAIL at the next layer:

**PKGS-04 job — `Run auto-pull e2e integration test (D-15 both clauses)` step:**
- `auto_pull_happy_path_mock` FAILED — panic at `crates/nono-cli/tests/auto_pull_e2e_linux.rs:240:5` with message `auto-pull happy path failed; stdout= stderr=` (stdout + stderr captured empty in the error string — the CLI under test likely exited before producing any output OR the test harness is mis-capturing it)
- `auto_pull_rejects_non_policy_pack_type` FAILED — panic at `crates/nono-cli/tests/auto_pull_e2e_linux.rs:569:5`
- `auto_pull_signature_failure_aborts` FAILED — panic at `crates/nono-cli/tests/auto_pull_e2e_linux.rs:458:5`
- 3 PASS (including `auto_pull_unknown_name_fails_closed`)
- Test result: FAILED. 3 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s — note **0.02s total** suggests every failing test panicked immediately rather than running real signing/network logic
- Exit code 101

**RESL-NIX job — `Cross-target clippy gate (Linux from Linux)` step:**
- `error: used unwrap_err() on a Result value` at `crates/nono-cli/src/profile_cmd.rs:3836:19`
- Code: `let msg = result.unwrap_err().to_string();`
- Clippy help: "consider using `expect_err()` to provide a better panic message"
- Lint: `clippy::unwrap_used` from `-D clippy::unwrap_used` (enforced per CLAUDE.md § Coding Standards bullet — unwrap policy)
- Exit code 101

### Error messages (verbatim, key excerpts)
```
PKGS-04:
thread 'auto_pull_happy_path_mock' (14241) panicked at crates/nono-cli/tests/auto_pull_e2e_linux.rs:240:5:
auto-pull happy path failed; stdout= stderr=
  nono v0.53.1
Profile 'mock-ns/mock-pack' not found locally.
nono: Registry error: registry returned HTTP 404 for mock-ns/mock-pack@latest
 req_count=1

thread 'auto_pull_rejects_non_policy_pack_type' (14243) panicked at crates/nono-cli/tests/auto_pull_e2e_linux.rs:569:5:
expected pack-type or signature rejection; got: 
  nono v0.53.1
Profile 'mock-ns/mock-pack' not found locally.
nono: Registry error: registry returned HTTP 404 for mock-ns/mock-pack@latest

thread 'auto_pull_signature_failure_aborts' (14244) panicked at crates/nono-cli/tests/auto_pull_e2e_linux.rs:458:5:
expected signature/verification-flavored error; got: 
  nono v0.53.1
Profile 'mock-ns/mock-pack' not found locally.
nono: Registry error: registry returned HTTP 404 for mock-ns/mock-pack@latest

test result: FAILED. 3 passed; 3 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s

RESL-NIX:
error: used `unwrap_err()` on a `Result` value
    --> crates/nono-cli/src/profile_cmd.rs:3836:19
3836 |         let msg = result.unwrap_err().to_string();
     |                   ^^^^^^^^^^^^^^^^^^^
     = note: if this value is an `Ok`, it will panic
     = help: consider using `expect_err()` to provide a better panic message
     = help: for further information visit https://rust-lang.github.io/rust-clippy/rust-1.95.0/index.html#unwrap_used
```

### Timeline
- Phase 37 was closed 2026-05-20 with VERIFICATION status `human_needed`. At Phase 37 close, the workflow file had never run live (commits unpushed).
- Two push-triggered runs at 2026-05-23T13:06:26Z (databaseId 26333501006) and 13:17:32Z (databaseId 26333731696) both FAILED at the original compile bugs (now resolved by quick-task 260523-kzd).
- Push-triggered run at 2026-05-23T19:36:35Z (databaseId 26341685999, SHA a8d771d5) is the first run where the compile layer PASSES. It fails at the next two layers documented above.
- This is the first time these failures have been observed (they were structurally hidden behind the compile errors). Both code paths (the e2e tests + the profile_cmd.rs:3836 unwrap_err) PRE-EXISTED — neither was introduced by 260523-kzd.

### Reproduction
**PKGS-04 runtime failures:**
1. Push any commit to `origin/main` (auto-triggers Phase 37 workflow)
2. Wait for PKGS-04 job to reach the `Run auto-pull e2e integration test (D-15 both clauses)` step
3. The 3 named tests fail in ~0.02s total — meaning they fail in the FIRST assertion (early-exit) rather than reaching the actual signing/network logic
4. Alternative: `gh workflow run phase-37-linux-resl.yml` on a fresh branch + `gh run watch <id>`
5. Local non-CI reproduction is NOT possible on Windows host: the tests are `#![cfg(target_os = "linux")]`-gated and require sigstore-sign CI fixtures + a real Linux runner with the test harness's CI-signed fixture pack

**RESL-NIX clippy failure:**
1. On a Linux host: `cargo clippy --workspace --tests --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used`
2. Reproducible across both real Linux and the `cross` Docker image (per Phase 50 precedent the Phase 41 RESL workflow uses)
3. The lint trips on `profile_cmd.rs:3836` — `result.unwrap_err().to_string()` — which is pre-existing code that the original BUG-2 compile failure was structurally hiding from the linter (workspace clippy fails compile before reaching lint pass)

## Current Focus

```yaml
hypothesis: "ROOT CAUSE CONFIRMED (two independent bugs, single shared mechanism for PKGS-04):
  PKGS-04 (all 3 failing tests): The mock TCP server only serves routes from an exact HashMap path match. The sign-fixture binary runs `cargo run --release -p sign-fixture` from the `target/fixture-pack` subdirectory, and the signing succeeds (confirmed by log: 'Signature created successfully!'). BUT the nono registry client makes its manifest request to `/mock-ns/mock-pack/manifest.json` and gets HTTP 404 — the log shows `nono: Registry error: registry returned HTTP 404 for mock-ns/mock-pack@latest` for ALL THREE failing tests. The cause is that the mock server routes are populated by the TEST code from fixtures loaded from NONO_FIXTURE_PACK_DIR, but the REGISTRY CLIENT in nono is using a different URL path than `/mock-ns/mock-pack/manifest.json` — it appends `@latest` to the manifest URL. The bundle.json in the fixture pack specifies `manifest_url: /mock-ns/mock-pack/manifest.json` but the nono registry client is fetching `/mock-ns/mock-pack@latest` instead (confirmed by the error message). This is a URL path construction mismatch in the production registry client: the auto-pull client appends `@latest` to the pack name in the URL, not to the bundle.json manifest_url. The mock routes contain `/mock-ns/mock-pack/manifest.json` but the client requests `/mock-ns/mock-pack@latest` (or a variant) which matches no route → 404 → all 3 tests fail identically with the same error. The auto_pull_unknown_name_fails_closed test PASSES because it expects 404.
  RESL-NIX clippy: profile_cmd.rs:3836 is inside #[cfg(test)] mod tests (which starts at line 3363). The workflow's clippy invocation includes `--tests`, which causes clippy to lint test-module code too. The `#[cfg(test)] mod tests` block at line 3363 is NOT annotated with `#[allow(clippy::unwrap_used)]` (confirmed: no such annotation present in the file). Other test modules in the workspace that DO have unwrap_err() sites are correctly annotated with `#[allow(clippy::unwrap_used)]` at the mod level (verified in network_policy.rs:357, trust_scan.rs:1120, signing.rs:521, wiring.rs:311/401, exec_identity.rs:116, dsse.rs:526, bundle.rs:1017, policy.rs:392, types.rs:496, nono-wfp-service.rs:1635, network.rs:1585, oauth2.rs:431, supervisor_macos.rs:189). The profile_cmd.rs test module at line 3363 is the ONLY test module with unwrap_err() that is missing this annotation. After fixing profile_cmd.rs, no other unwrap_err() sites will surface (all others are already protected by module-level #[allow] annotations)."
test: completed
expecting: "PKGS-04 root cause: nono registry client constructs manifest URL differently from what the mock's bundle.json specifies — confirmed by the identical 404 error across all 3 failing tests. RESL-NIX root cause: missing #[allow(clippy::unwrap_used)] on profile_cmd.rs test module at line 3363."
next_action: "DONE — root causes confirmed. Return root cause report to operator."
```

## Evidence

- timestamp: 2026-05-23T19:36:35Z
  source: gh run list --workflow=phase-37-linux-resl.yml
  observation: "Run 26341685999 on SHA a8d771d5 (push event triggered by docs(quick-260523-kzd) commit). status=completed, conclusion=failure. Both jobs (PKGS-04 + RESL-NIX) report failure. Run completed 2026-05-23T19:47:xxxZ (~10 minutes wall-clock)."

- timestamp: 2026-05-23T19:44:36Z
  source: gh run view 26341685999 --log-failed
  observation: |
    PKGS-04 fails at step 'Run auto-pull e2e integration test (D-15 both clauses)':
    - auto_pull_happy_path_mock panics at auto_pull_e2e_linux.rs:240 with "auto-pull happy path failed; stdout= stderr="
    - auto_pull_rejects_non_policy_pack_type panics at line 569
    - auto_pull_signature_failure_aborts panics at line 458
    - auto_pull_unknown_name_fails_closed PASSES
    - 3 passed; 3 failed; 0.02s total runtime → all 3 fail in FIRST assertion (early-exit pattern)
    - Empty stdout AND empty stderr in the panic message → the CLI under test exited before producing any output, OR the failure is at a setup/precondition step before invoking the CLI

- timestamp: 2026-05-23T19:47:48Z
  source: gh run view 26341685999 --log-failed (RESL-NIX job)
  observation: |
    RESL-NIX fails at step 'Cross-target clippy gate (Linux from Linux)':
    - error: used `unwrap_err()` on a `Result` value
    - Location: crates/nono-cli/src/profile_cmd.rs:3836:19
    - Code: `let msg = result.unwrap_err().to_string();`
    - Clippy lint: `clippy::unwrap_used` (denied via -D)
    - This is the FIRST time the cross-target Linux clippy gate has executed on this codebase
    - Other unwrap_used sites likely exist; this audit run only shows the first error encountered before clippy fails fast

- timestamp: 2026-05-23T19:36:35Z
  source: workspace context
  observation: |
    The quick-task 260523-kzd diff did NOT touch crates/nono-cli/tests/auto_pull_e2e_linux.rs or crates/nono-cli/src/profile_cmd.rs.
    - 260523-kzd touched: tools/sign-fixture/ (new), Cargo.toml (root members list), Cargo.lock, .github/workflows/phase-37-linux-resl.yml (PKGS-04 step), crates/nono-cli/src/exec_strategy/supervisor_linux.rs (3 lines)
    - Both new failure sites pre-existed; the original BUG-1 + BUG-2 compile failures were structurally hiding them
    - The PKGS-04 runtime failure is downstream of the new sign-fixture binary invocation; possible the new binary produces a different signed artifact than the old `--example sign_blob` would have
    - The RESL-NIX clippy failure is on pre-existing profile_cmd.rs code; pure code-quality lint, unrelated to sign-fixture

- timestamp: 2026-05-23T19:44:36Z (full log extraction)
  source: gh run view 26341685999 --log --job=77544741038 (PKGS-04 job ID confirmed)
  observation: |
    SIGNING STEP: SUCCEEDED. Sign fixture artifact step ran successfully:
    - cargo run --release -p sign-fixture -- artifact.tar.gz -o artifact.tar.gz.sigstore.json
    - Output: "Signature created successfully!" + "Bundle: artifact.tar.gz.sigstore.json"
    - SIGSTORE_ID_TOKEN_AUDIENCE=sigstore was set; ambient OIDC detected: repo:oscarmackjr-twg/nono:ref:refs/heads/main
    - Issuer: https://token.actions.githubusercontent.com (matches NONO_TRUST_OIDC_ISSUER)
    - ls -la artifact.tar.gz.sigstore.json: -rw-r--r-- 1 runner runner 11165 May 23 19:41
    - So the fixture files (bundle.json, manifest.json, artifact.tar.gz, artifact.tar.gz.sigstore.json) were ALL present in target/fixture-pack

    TEST STEP: Full panic messages extracted (previously truncated):
    - auto_pull_happy_path_mock panic body: "auto-pull happy path failed; stdout= stderr=\n  nono v0.53.1\nProfile 'mock-ns/mock-pack' not found locally.\nnono: Registry error: registry returned HTTP 404 for mock-ns/mock-pack@latest\n req_count=1"
    - auto_pull_rejects_non_policy_pack_type panic body: "expected pack-type or signature rejection; got: \n  nono v0.53.1\nProfile 'mock-ns/mock-pack' not found locally.\nnono: Registry error: registry returned HTTP 404 for mock-ns/mock-pack@latest"
    - auto_pull_signature_failure_aborts panic body: "expected signature/verification-flavored error; got: \n  nono v0.53.1\nProfile 'mock-ns/mock-pack' not found locally.\nnono: Registry error: registry returned HTTP 404 for mock-ns/mock-pack@latest"

    CRITICAL OBSERVATION: All 3 failing tests show the SAME error: the nono binary's registry client reports "HTTP 404 for mock-ns/mock-pack@latest". The mock server has routes keyed at `/mock-ns/mock-pack/manifest.json` (set up from bundle.json + fixture fixtures). The production registry client is NOT fetching `/mock-ns/mock-pack/manifest.json` — it is fetching a URL containing `mock-ns/mock-pack@latest`. The `@latest` suffix is not present in the bundle.json `manifest_url` field. req_count=1 for the happy-path test means exactly one request reached the mock (likely the bundle.json fetch), then the manifest fetch to `@latest`-suffixed URL returned 404.

- timestamp: 2026-05-23T19:44:36Z (workspace code audit)
  source: Read crates/nono-cli/src/profile_cmd.rs lines 3363-3870
  observation: |
    - #[cfg(test)] mod tests { starts at line 3363
    - NO #[allow(clippy::unwrap_used)] annotation on this mod block (confirmed by grep: zero matches)
    - unwrap_err() call at line 3836 is inside `fn read_regular_file_rejects_symlink` which is a #[cfg(unix)] #[test] fn inside that module
    - All OTHER test modules with unwrap_err() across the workspace have #[allow(clippy::unwrap_used)] at their mod level:
      network_policy.rs:357, trust_scan.rs:1120, signing.rs:521, wiring.rs:311+401,
      exec_identity.rs:116, dsse.rs:526, bundle.rs:1017, policy.rs:392, types.rs:496,
      nono-wfp-service.rs:1635, network.rs:1585, oauth2.rs:431, supervisor_macos.rs:189,
      supervisor_linux.rs:1318+1534
    - profile_cmd.rs is the sole test module with unwrap_err() missing this annotation
    - After fixing profile_cmd.rs, clippy should pass (no other unprotected unwrap_err sites exist)

## Eliminated

- Hypothesis that signing step failed: ELIMINATED. The signing step completed successfully with exit 0, producing a valid 11165-byte bundle.
- Hypothesis that NONO_FIXTURE_PACK_DIR was unset or wrong path: ELIMINATED. fixture_pack_dir() check passes (tests proceed past the early-return guard) since req_count=1 for happy-path (means the nono binary ran and made a network request).
- Hypothesis that sign-fixture output format differs from what tests expect: ELIMINATED. The 3 failing tests all fail at the assertion that checks `output.status.success()` or error message content — the nono binary DID run, DID contact the mock, DID get a response. The issue is the URL path mismatch, not file format.
- Hypothesis that multiple independent unwrap_err() sites would cascade after fixing profile_cmd.rs: ELIMINATED. All other unwrap_err() sites in the workspace are inside modules already annotated with #[allow(clippy::unwrap_used)].

## Resolution

ROOT CAUSE FOUND — diagnose-only per operator request; fix to land as a follow-up quick-task.

**BUG-A (PKGS-04 — 3 failing tests, shared root cause):**
The nono registry client constructs the manifest URL by appending `@latest` to the pack name (producing a path like `/mock-ns/mock-pack@latest` or similar) rather than using the `manifest_url` field from bundle.json verbatim. The fixture mock server routes are keyed to `/mock-ns/mock-pack/manifest.json` (the value in `manifest_url` in bundle.json). The mismatch causes HTTP 404 from the mock for all three tests that exercise the manifest-fetch code path. `auto_pull_unknown_name_fails_closed` passes because it serves 404 for everything and only asserts that the binary fails — which it does.

**BUG-B (RESL-NIX clippy — single lint violation):**
`crates/nono-cli/src/profile_cmd.rs`'s `#[cfg(test)] mod tests` block (starting line 3363) lacks the `#[allow(clippy::unwrap_used)]` annotation that every other test module with `unwrap_err()` calls carries. The workflow's clippy invocation includes `--tests`, which causes clippy to lint test-module code. One `unwrap_err()` at line 3836 (inside `read_regular_file_rejects_symlink`) is thus flagged.

## TDD Checkpoint

(not applicable — diagnose-only investigation)

## Cross-references

- Prior debug session: `.planning/debug/phase-37-resl-failure.md` (status: root_cause_found; the original BUG-1 + BUG-2 that 260523-kzd fixed)
- Quick task that fixed prior bugs: `.planning/quick/260523-kzd-fix-phase-37-resl-workflow-compile-bugs-/260523-kzd-SUMMARY.md`
- Workflow file: `.github/workflows/phase-37-linux-resl.yml`
- Tests: `crates/nono-cli/tests/auto_pull_e2e_linux.rs` (lines 240, 458, 569)
- Lint site: `crates/nono-cli/src/profile_cmd.rs:3836`
- New sign-fixture: `tools/sign-fixture/src/main.rs`
- Phase 37 close VERIFICATION: `.planning/phases/37-linux-resl-backends-pkgs-auto-pull/37-VERIFICATION.md`
- Phase 37 close PLANS: `.planning/phases/37-linux-resl-backends-pkgs-auto-pull/37-04-PLAN.md` + `37-05-PLAN.md` (original workflow authorship)
- CLAUDE.md § Coding Standards § Unwrap Policy: enforces `-D clippy::unwrap_used`
- CLAUDE.md § Cross-target clippy verification: cross-target Linux clippy MUST run on Linux toolchain
