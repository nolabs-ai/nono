---
slug: phase-37-resl-failure
status: root_cause_found
trigger: "Phase 37 RESL workflow has been failing on push-triggered runs. Most recent failure: databaseId 26333731696 at 2026-05-23T13:17:32Z. Failed job: 'Phase 37 PKGS-04 (auto-pull e2e)'. This is a blocker for Plan 46-02 REQ-CI-FU-01 which requires a green live run of phase-37-linux-resl.yml on ubuntu-24.04."
goal: find_root_cause_only
created: 2026-05-23
updated: 2026-05-23
phase: 46
related_phases: [37]
related_requirements: [REQ-CI-FU-01]
---

# Debug: Phase 37 RESL workflow failure

## Symptoms

### Expected behavior
`.github/workflows/phase-37-linux-resl.yml` runs green on ubuntu-24.04 with both jobs (`resl-nix` and `pkgs-auto-pull`) reporting `conclusion=success`. The `Wait for user session and verify cpu controller delegated` step prints `OK: cpu controller delegated`. Integration tests pass: `linux_memory_limit_oom_kills_child`, `linux_cpu_percent_throttles_yes_loop`, `linux_max_processes_5_fork_bomb_contained`, `linux_max_processes_blocks_eleventh_fork`, `auto_pull_happy_path_mock`, `auto_pull_unknown_name_fails_closed`, `auto_pull_no_auto_pull_flag_falls_back_to_profile_not_found`, `auto_pull_signature_failure_aborts`, `auto_pull_rejects_non_policy_pack_type`. CPU-throttle test measured average falls within `[15, 40]`% band.

### Actual behavior
Workflow run consistently reports `conclusion=failure`. Most recent failure visible at databaseId 26333731696 — push event 2026-05-23T13:17:32Z on `main`. Job name reporting failure: `Phase 37 PKGS-04 (auto-pull e2e)`. Prior run at databaseId 26333501006 (2026-05-23T13:06:26Z, also push event) also failed in the same job. The `CI` workflow on the same commits succeeded — failures are isolated to `phase-37-linux-resl.yml`.

### Error messages
Initial log inspection via `gh run view 26333731696 --log-failed | tail -30` returned only post-step cleanup output (Removing SSH command configuration, Removing HTTP extra header, Removing credentials, Cleaning up orphan processes). Actual failing assertion / panic / exit code is upstream of the visible cleanup tail — must be retrieved via wider log capture (e.g. `--log` not `--log-failed`, or filtered to test runner output / assertion failure / panic).

### Timeline
Workflow file `.github/workflows/phase-37-linux-resl.yml` was added by Plan 37-04 and populated by Plan 37-05 during Phase 37 (closed 2026-05-20). Per 37-VERIFICATION.md `status: human_needed`, the workflow has structurally been correct since Phase 37 close but had NEVER run successfully — the deferred verification item explicitly says "Phase 37 commits are unpushed (`git log origin/main..HEAD` shows 25+ Phase-37 commits)" and "`gh workflow list` does not yet list 'Phase 37 Linux RESL' — the workflow has never run." First successful WORKFLOW RUN dispatch may be the recent push-triggered runs at 2026-05-23T13:06:26Z and 13:17:32Z — both failed. No prior successful run exists to compare against.

### Reproduction
1. Push a commit to `origin/main`
2. Workflow `Phase 37 Linux RESL` triggers automatically per its push triggers
3. After ~N minutes (per the integration test budget on cgroup-v2 hosts), the `Phase 37 PKGS-04 (auto-pull e2e)` job reports failure

To reproduce manually for investigation: `gh workflow run phase-37-linux-resl.yml` (workflow_dispatch is configured per Plan 37-05 spec) and wait via `gh run watch <run-id>`.

## Current Focus

```yaml
hypothesis: "CONFIRMED — two distinct compile-time failures, one in each job."
test: "Full log capture via gh run view 26333731696 --log — completed."
expecting: "Compile errors pinpointed to specific source files."
next_action: "Root cause found — report ready."
```

## Evidence

- timestamp: 2026-05-23
  source: gh run list output
  observation: "Recent push runs on main: databaseId 26333731714 (CI) success; databaseId 26333731696 (Phase 37 Linux RESL) failure; databaseId 26333501006 (Phase 37 Linux RESL) failure at earlier push 13:06:26Z. CI workflow is GREEN on the same commits — failures are scoped to phase-37-linux-resl.yml only."

- timestamp: 2026-05-23
  source: gh run view 26333731696 --log-failed | tail -30
  observation: "Tail showed only post-step cleanup output (Removing SSH command, Removing HTTP extra header, Removing credentials config, Cleaning up orphan processes). The cleanup runs at the end of every job whether or not the job failed — meaning the actual failure occurred BEFORE these cleanup steps and was truncated out of the visible window. Need wider log capture."

- timestamp: 2026-05-23
  source: 37-VERIFICATION.md frontmatter (read during /gsd-execute-phase 46 session)
  observation: "Phase 37 verification status: human_needed since 2026-05-20T03:42:19Z. Reported score: 5/6 must-haves verified (Success Criterion 6 requires post-merge CI confirmation). Deferred items explicitly call out: the workflow file exists locally and is YAML-valid, but Phase 37 commits were unpushed at Phase 37 close; the workflow had never run successfully prior to the recent push-triggered runs that both failed. The structural correctness was locally verified but live runtime correctness has not yet been demonstrated on ubuntu-24.04."

- timestamp: 2026-05-23
  source: 37-VERIFICATION.md human_verification block
  observation: "Five human-verification items defined: (1) workflow runs green on ubuntu-24.04 with both jobs success + cpu controller delegated step prints OK + 9 integration tests pass + CPU throttle test in [15, 40]% band; (2) REQ-RESL-NIX-02 CPU throttling actually fires on cgroup v2 host (not silently skipped via require_cpu_controller!); (3) REQ-PKGS-04 acceptance #1 (auto_pull_happy_path_mock) e2e on Linux runner with CI-signed fixture; (4) `nono pull --no-auto-pull foo` clap-parse rejection; (5) doc-flag check script passes on --no-auto-pull. Items 1-3 require live runner execution; items 4-5 are local-host verifiable."

- timestamp: 2026-05-23
  source: gh run view 26333731696 --log (full log, PKGS-04 job)
  observation: |
    PKGS-04 fails at step 'Build workspace and sigstore-sign example' with exit code 101 at 2026-05-23T13:22:32Z.
    Error: error[E0432]: unresolved import `chrono` at sigstore-sign-0.7.0/examples/sign_blob.rs:203:17
    Error: error[E0433]: cannot find module or crate `tokio` in this scope at sign_blob.rs:47:3
    Error: error[E0752]: `main` function is not allowed to be `async` at sign_blob.rs:48:1
    Error: could not compile `sigstore-sign` (example "sign_blob") due to 3 previous errors
    Root cause: `sigstore-sign 0.7.0` declares `tokio` and `chrono` as dev-dependencies, NOT regular dependencies.
    When `cargo build --release -p sigstore-sign --example sign_blob` is run from a CONSUMER workspace
    (rather than sigstore-sign's own workspace), Cargo does NOT fetch external crates' dev-dependencies.
    The example compiles fine in the sigstore-rs upstream workspace but fails when built as a registry dep.

- timestamp: 2026-05-23
  source: gh run view 26333731696 --log (full log, RESL-NIX job)
  observation: |
    RESL-NIX fails at step 'Cross-target clippy gate (Linux from Linux)' with exit code 101 at 2026-05-23T13:26:18Z.
    Three compile errors in crates/nono-cli/src/exec_strategy/supervisor_linux.rs:
    error[E0107]: type alias takes 1 generic argument but 2 were supplied — at lines 1451, 1474, 1505.
    error[E0277]: `?` couldn't convert the error to `nono::NonoError` — at the same three functions.
    Root cause: The `cgroup` module at line 859 imports `use nono::{NonoError, Result, ...}` which shadows
    std::result::Result. The three test functions declare `-> Result<(), Box<dyn std::error::Error>>`,
    using two type arguments. nono::Result<T> is `type Result<T> = std::result::Result<T, NonoError>` —
    a single-argument alias. Two-arg form is only valid for std::result::Result. This is a test code bug.

- timestamp: 2026-05-23
  source: ~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/sigstore-sign-0.7.0/Cargo.toml
  observation: |
    Confirmed: sigstore-sign 0.7.0 Cargo.toml lists `tokio 1.47 (full)` and `chrono 0.4 (serde)` ONLY as
    [dev-dependencies]. They are NOT in [dependencies]. The [example] entries for sign_blob are declared
    explicitly (autoexamples = false). Dev-deps of external registry crates are never fetched by Cargo
    from a consumer workspace, making it structurally impossible to build this example outside sigstore-rs's
    own workspace without adding tokio/chrono as regular deps or using a different approach.

## Eliminated

- Sigstore OIDC token / id-token: write permission misconfiguration — ELIMINATED. The workflow never reaches
  the signing step; it fails at the cargo build step before any OIDC token is requested.
- auto_pull_happy_path_mock test assertion failure — ELIMINATED. The test never runs; compilation fails first.
- Transitive dep bump or MSRV change — ELIMINATED. The cargo build --workspace succeeds; only the external
  sigstore-sign example compilation fails.
- Environmental issue with ubuntu-24.04 runner (apt, cgroup drift) — ELIMINATED. The apt install and
  system setup steps complete successfully. The RESL-NIX failure is a compile error, not a runtime failure.
- CPU-throttle test flakiness or cgroup v2 runner issue — ELIMINATED. The RESL-NIX test never runs;
  compilation fails at the clippy gate before integration tests are invoked.

## Resolution

root_cause: |
  Two independent compile-time bugs prevent both jobs from completing. Neither job reaches its integration
  test phase.

  BUG-1 (PKGS-04): The workflow step 'Build workspace and sigstore-sign example' runs
  `cargo build --release -p sigstore-sign --example sign_blob`. This command attempts to build the
  sign_blob example from the sigstore-sign 0.7.0 registry crate. However, sign_blob.rs requires
  `chrono` and `tokio` which are only dev-dependencies in sigstore-sign's own Cargo.toml — not regular
  dependencies. When building from a consumer workspace, Cargo does not fetch dev-dependencies of
  external registry crates, so `chrono` and `tokio` are unavailable and compilation fails with
  E0432/E0433/E0752 errors.

  BUG-2 (RESL-NIX): The 'Cross-target clippy gate (Linux from Linux)' step compiles nono-cli tests with
  --tests. The `cgroup` module in crates/nono-cli/src/exec_strategy/supervisor_linux.rs imports
  `use nono::Result` (line 859), which is a single-argument type alias defined as
  `type Result<T> = std::result::Result<T, NonoError>`. Three test functions at lines 1451, 1474, and
  1505 are declared with `-> Result<(), Box<dyn std::error::Error>>` — which requires two type arguments.
  This two-argument form is valid for std::result::Result but not for the single-argument nono::Result.
  The compiler emits E0107 (wrong arity) and E0277 (? operator type mismatch) for each function.

fix: "NOT APPLIED — diagnose-only mode. See suggested fix categories in Resolution section."

## TDD Checkpoint

(not applicable for diagnose-only investigation; if fix is planned later and TDD_MODE=true, the fix phase would add a regression test before changing code)
