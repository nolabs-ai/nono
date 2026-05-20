---
phase: 44-review-polish-test-hygiene-drain
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - crates/nono-cli/src/exec_strategy/supervisor_linux.rs
  - crates/nono/src/error.rs
  - crates/nono-cli/src/cli.rs
  - crates/nono-cli/src/diagnostic_formatter.rs
  - crates/nono-cli/src/pack_update_hint.rs
  - crates/nono-cli/src/platform.rs
  - crates/nono-cli/src/sandbox_prepare.rs
  - crates/nono-cli/src/package_cmd.rs
  - crates/nono-cli/src/session_commands.rs
  - crates/nono-cli/src/session_commands_windows.rs
  - crates/nono-cli/src/format_util.rs
  - crates/nono/src/trust/signing.rs
  - crates/nono/src/trust/mod.rs
  - crates/nono/src/undo/snapshot.rs
  - crates/nono-cli/tests/common/test_env.rs
  - crates/nono-cli/tests/auto_pull_e2e_linux.rs
  - crates/nono-cli/tests/resl_nix_linux.rs
  - .github/workflows/phase-37-linux-resl.yml
  - .github/scripts/check-cli-doc-flags.sh
  - .planning/todos/pending/44-validate-restore-target-fd-relative-hardening.md
autonomous: true
requirements:
  - REQ-REVIEW-FU-01
must_haves:
  truths:
    - "All 16 WARNING findings carry an explicit disposition row in PLAN.md — no silent ignore (Roadmap SC#1)"
    - "All 12 INFO findings carry an explicit disposition row in PLAN.md (D-44-B5 default-fix)"
    - "Phase 37 WR-09 ships a production configured_oidc_issuer reader honoring NONO_TRUST_OIDC_ISSUER (D-44-B3)"
    - "Phase 43 WR-05 synchronous pack-update path is fully deleted; first-run users get background-only refresh (D-44-B2 option b)"
    - "Phase 43 WR-01 validate_restore_target doc documents the residual TOCTOU race window AND a follow-up todo file exists (D-44-B4)"
    - "Phase 43 WR-02 / WR-04 / WR-06 platform.rs correctness fixes ship with in-file regression tests"
    - "Phase 37 WR-03 / WR-04 / IN-01 test thread-safety fixes use the canonical lock_env + EnvVarGuard (D-44-E6)"
    - "tests/common/test_env.rs gate widened to any(target_os = windows, target_os = linux) AND a lock_env() mirror is added (PATTERNS.md friction point)"
    - "Cross-target clippy was run for every cfg-gated Unix-touching commit per D-44-E2 + cross-target-verify-checklist (or PARTIAL when toolchain unavailable)"
    - "Every commit carries a DCO Signed-off-by trailer (CLAUDE.md)"
  artifacts:
    - path: "crates/nono/src/trust/signing.rs"
      provides: "Production configured_oidc_issuer reader for NONO_TRUST_OIDC_ISSUER"
      contains: "fn configured_oidc_issuer"
    - path: "crates/nono-cli/src/pack_update_hint.rs"
      provides: "Background-only pack-update refresh (synchronous path deleted)"
      contains: "refresh_in_background"
      must_not_contain: "fn refresh_synchronous"
    - path: "crates/nono-cli/src/platform.rs"
      provides: "Fixed parse_windows_registry_value (case-insensitive + None on malformed REG_DWORD) + symmetric compare_versions"
      contains: "eq_ignore_ascii_case"
    - path: "crates/nono/src/undo/snapshot.rs"
      provides: "Residual TOCTOU doc note on validate_restore_target"
      contains: "Residual race window"
    - path: "crates/nono-cli/src/exec_strategy/supervisor_linux.rs"
      provides: "Deduplicated cgroup-v2 boot-flag hint via CGROUP_V2_HINT const"
      contains: "CGROUP_V2_HINT"
    - path: "crates/nono-cli/tests/common/test_env.rs"
      provides: "Linux+Windows-gated mirror of EnvVarGuard + lock_env mutex"
      contains: "lock_env"
    - path: ".planning/todos/pending/44-validate-restore-target-fd-relative-hardening.md"
      provides: "Breadcrumb for fd-relative O_NOFOLLOW hardening of validate_restore_target"
    - path: ".github/scripts/check-cli-doc-flags.sh"
      provides: "Multi-line arg accumulator + hide=true skip in awk pipeline"
      contains: "in_arg"
    - path: ".github/workflows/phase-37-linux-resl.yml"
      provides: "WR-08 env injection; WR-09 paired with production wire-up"
  key_links:
    - from: "crates/nono-cli/tests/auto_pull_e2e_linux.rs"
      to: "crates/nono-cli/tests/common/test_env.rs"
      via: "mod common; use common::test_env::{EnvVarGuard, lock_env}"
      pattern: "use common::test_env"
    - from: "crates/nono/src/trust/signing.rs::configured_oidc_issuer"
      to: ".github/workflows/phase-37-linux-resl.yml NONO_TRUST_OIDC_ISSUER env var"
      via: "std::env::var read at signature verification time"
      pattern: "NONO_TRUST_OIDC_ISSUER"
    - from: "crates/nono-cli/src/pack_update_hint.rs::save_state"
      to: "atomic write pattern from crates/nono-cli/src/package.rs::write_lockfile"
      via: "fs::write(tmp_path) + fs::rename(tmp_path, path)"
      pattern: "json.tmp"
    - from: "crates/nono-cli/src/exec_strategy/supervisor_linux.rs"
      to: "crates/nono/src/error.rs"
      via: "shared CGROUP_V2_HINT const"
      pattern: "CGROUP_V2_HINT"
---

<objective>
Drain the 16-WARNING + 12-INFO REVIEW.md backlog inherited from Phase 37 + Phase 43 in a single `chore(v2.6-followup):` plan, satisfying REQ-REVIEW-FU-01. Every finding gets an explicit disposition row in the canonical table below — no silent ignore (Roadmap SC#1). The phase ships ~5-7 review-friendly commits grouped by warning class per D-44-A4, including one `feat(44-01):` commit that wires the production OIDC issuer reader (WR-09 P37 per D-44-B3) and one `docs(44-01):` commit documenting the residual TOCTOU race in `validate_restore_target` (WR-01 P43 per D-44-B4).

Purpose: Phase 44 close becomes the v2.6 quiet-baseline anchor SHA. Phase 46's baseline-aware CI lane diff (REQ-CI-FU-03) gates against this baseline; introducing a noisy backlog now poisons that gate. Drain now or pay later.

Output: A clean `crates/nono-cli/src/` + `crates/nono/src/` + `.github/` surface with zero REVIEW findings unaddressed, one new production code path (`configured_oidc_issuer`), one new follow-up todo, and a widened `tests/common/test_env.rs` gate enabling cross-platform integration test isolation.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md
@.planning/REQUIREMENTS.md
@.planning/phases/44-review-polish-test-hygiene-drain/44-CONTEXT.md
@.planning/phases/44-review-polish-test-hygiene-drain/44-PATTERNS.md
@.planning/phases/37-linux-resl-backends-pkgs-auto-pull/37-REVIEW.md
@.planning/phases/43-upst5-sync-execution/43-REVIEW.md
@.planning/templates/cross-target-verify-checklist.md
@CLAUDE.md

<interfaces>
<!-- Existing primitives the executor composes. Extracted from codebase. -->

From crates/nono/src/trust/signing.rs (existing — DO NOT re-define):
```rust
pub fn validate_oidc_issuer(iss: &str, pin: &str) -> Result<()>;   // lines 86-123
pub const GITLAB_COM_OIDC_ISSUER: &str = "https://gitlab.com";     // line ~128
pub const GITHUB_ACTIONS_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";  // line ~134
```
Reader to ADD (WR-09 P37): `pub fn configured_oidc_issuer() -> Result<String>` — env-var first, fall back to `GITHUB_ACTIONS_OIDC_ISSUER`, fail-closed on unparseable URL via `url::Url::parse`.

From crates/nono/src/error.rs:
```rust
NonoError::ConfigParse(String)
NonoError::UnsupportedKernelFeature { feature: String, hint: String }
// line 425-426: test-mod-only `const LOCKED_HINT: &str = "cgroup v2 required; ..."`
//   — promote to `pub const CGROUP_V2_HINT: &str = ...` at module level.
```

From crates/nono-cli/src/test_env.rs (binary-only — NOT visible to integration tests):
```rust
pub static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub fn lock_env() -> std::sync::MutexGuard<'static, ()>;
```
Mirror to ADD in `crates/nono-cli/tests/common/test_env.rs` (gate widened to any(windows, linux)).

From crates/nono-cli/src/package.rs:367-379 (canonical atomic-write reference):
```rust
let tmp_path = path.with_extension("json.tmp");
fs::write(&tmp_path, format!("{json}\n")).map_err(NonoError::Io)?;
fs::rename(&tmp_path, &path).map_err(NonoError::Io)?;
```
</interfaces>
</context>

## Canonical Disposition Table (REQ-REVIEW-FU-01)

Per D-44-A3, this table is the canonical source. **Every WR + IN gets a row** — 16 WARNING + 12 INFO = 28 rows. The `Commit Ref` column is filled in by execute-phase after each commit lands.

| ID         | Source       | File:Line                                                                                                  | Category                  | Disposition                                                                                                                                                                | Commit Group               | Commit Ref |
|------------|--------------|------------------------------------------------------------------------------------------------------------|---------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------|------------|
| WR-01-P37  | 37-REVIEW.md | .github/scripts/check-cli-doc-flags.sh:24                                                                  | CI hygiene                | **fix** — accumulate multi-line `#[arg(...)]` in awk pipeline until closing `)]`                                                                                            | CI hygiene                 | TBD        |
| WR-02-P37  | 37-REVIEW.md | crates/nono-cli/src/exec_strategy/supervisor_linux.rs:891,901,910,981,993,997 + crates/nono/src/error.rs:421 | platform / quality        | **fix** — extract `pub const CGROUP_V2_HINT: &str` in error.rs; reference at all 6 supervisor_linux.rs sites                                                                | platform.rs correctness    | TBD        |
| WR-03-P37  | 37-REVIEW.md | crates/nono-cli/tests/auto_pull_e2e_linux.rs:29-61                                                         | test reliability          | **fix** — `mod common; use common::test_env::{EnvVarGuard, lock_env};` + `let _lock = lock_env();` per test; drop file-local `EnvGuard`; drop `--test-threads=1` from workflow | test thread-safety         | TBD        |
| WR-04-P37  | 37-REVIEW.md | crates/nono-cli/tests/auto_pull_e2e_linux.rs:218,280,329,391-465,492                                       | test correctness          | **fix** — pin XDG_CONFIG_HOME to tempdir alongside NONO_TEST_HOME in all 5 tests                                                                                            | test thread-safety         | TBD        |
| WR-05-P37  | 37-REVIEW.md | crates/nono/Cargo.toml:48 (callsites at `VerificationPolicy::default()`)                                   | security-relevant pin     | **fix** — add unit test asserting `VerificationPolicy::default().verify_sct == true`                                                                                       | misc INFO drain (test pin) | TBD        |
| WR-06-P37  | 37-REVIEW.md | crates/nono-cli/tests/resl_nix_linux.rs:37-39                                                              | test heuristic            | **fix** — `nix::unistd::access(path, AccessFlags::W_OK).is_ok()`                                                                                                            | misc INFO drain            | TBD        |
| WR-07-P37  | 37-REVIEW.md | crates/nono-cli/tests/resl_nix_linux.rs:212-253                                                            | test coverage drift       | **fix** — `require_cgroup_v2!()` macro at top of file; skip-if-unavailable                                                                                                  | misc INFO drain            | TBD        |
| WR-08-P37  | 37-REVIEW.md | .github/workflows/phase-37-linux-resl.yml:135                                                              | CI hygiene                | **fix** — `env: WORKSPACE: ${{ github.workspace }}` then `"$WORKSPACE"` in shell                                                                                            | CI hygiene                 | TBD        |
| WR-09-P37  | 37-REVIEW.md | .github/workflows/phase-37-linux-resl.yml:294 + crates/nono/src/trust/signing.rs (NEW reader)              | CI misleading / prod gap  | **fix (feat-class per D-44-B3)** — `configured_oidc_issuer()` production reader; reads NONO_TRUST_OIDC_ISSUER; fail-closed via url::Url::parse                              | feat(44-01) WR-09          | TBD        |
| WR-10-P37  | 37-REVIEW.md | .github/scripts/check-cli-doc-flags.sh:64-67 + crates/nono-cli/src/cli.rs:1773 (`hide = true`)             | parser blind spot         | **fix** — in awk, skip fields whose accumulated `attr` contains `hide = true`                                                                                              | CI hygiene                 | TBD        |
| IN-01-P37  | 37-REVIEW.md | crates/nono-cli/tests/auto_pull_e2e_linux.rs:44-51                                                         | test correctness (Drop)   | **fix** — superseded by WR-03/WR-04 (file-local EnvGuard deleted)                                                                                                          | test thread-safety         | TBD        |
| IN-02-P37  | 37-REVIEW.md | crates/nono-cli/tests/auto_pull_e2e_linux.rs:334-372                                                       | test asset                | **defer** (planner-discretion per D-44-B5) — harmless detached listener; file follow-up todo if pattern proliferates                                                       | misc INFO drain            | TBD        |
| IN-03-P37  | 37-REVIEW.md | crates/nono-cli/src/session_commands.rs:691-714 + session_commands_windows.rs:610-628                      | dedup / refactor          | **fix** — extract `format_bytes_short` into NEW `crates/nono-cli/src/format_util.rs`; both Unix + Windows import                                                            | misc INFO drain            | TBD        |
| IN-04-P37  | 37-REVIEW.md | crates/nono-cli/src/cli.rs:1484-1496                                                                       | doc / help-text           | **verify-and-fix-if-needed** — run `cargo run -- run --help` and grep for NONO_NO_AUTO_PULL; if clap auto-renders, no source change                                         | misc INFO drain            | TBD        |
| IN-05-P37  | 37-REVIEW.md | crates/nono-cli/tests/auto_pull_e2e_linux.rs:313-316                                                       | test brittleness          | **fix** — widen `req_count <= 2` to `req_count <= 4`; document expected request set                                                                                         | test thread-safety         | TBD        |
| IN-06-P37  | 37-REVIEW.md | crates/nono-cli/src/exec_strategy/supervisor_linux.rs:888-1000                                             | readability               | **fix** — one-line module-doc comment at top of `cgroup` mod enumerating the 5 sites                                                                                       | platform.rs correctness    | TBD        |
| IN-07-P37  | 37-REVIEW.md | crates/nono-cli/src/diagnostic_formatter.rs:25-41                                                          | grep-contract             | **fix** — extend the existing doc comment to surface the integration-test grep contract                                                                                    | misc INFO drain            | TBD        |
| WR-01-P43  | 43-REVIEW.md | crates/nono/src/undo/snapshot.rs:595-687                                                                   | security (TOCTOU residual)| **doc-only** (D-44-B4) — extend doc comment verbatim per 43-REVIEW.md:99-109; file follow-up todo                                                                          | docs(44-01) WR-01-P43      | TBD        |
| WR-02-P43  | 43-REVIEW.md | crates/nono-cli/src/platform.rs:146-169                                                                    | correctness (REG_DWORD)   | **fix** — on REG_DWORD parse failure, return None (not raw "0xZZZ" string); verbatim per 43-REVIEW.md:138-146                                                              | platform.rs correctness    | TBD        |
| WR-03-P43  | 43-REVIEW.md | crates/nono-cli/src/pack_update_hint.rs:290-304                                                            | UX / semver               | **fix** — strip pre-release/build-metadata before splitn; suppress hint on either-side parse fail; verbatim per 43-REVIEW.md:172-188                                       | pack_update_hint UX        | TBD        |
| WR-04-P43  | 43-REVIEW.md | crates/nono-cli/src/platform.rs:583-597                                                                    | Ord antisymmetry          | **fix** — symmetric non-numeric arm; verbatim per 43-REVIEW.md:223-233; regression test pins antisymmetry                                                                  | platform.rs correctness    | TBD        |
| WR-05-P43  | 43-REVIEW.md | crates/nono-cli/src/pack_update_hint.rs:84-99 + sandbox_prepare.rs:108-112                                 | CLAUDE.md startup latency | **fix (option b per D-44-B2)** — DELETE `refresh_synchronous` entirely; always background-refresh; first-run hint deferred to 2nd run                                       | pack_update_hint UX        | TBD        |
| WR-06-P43  | 43-REVIEW.md | crates/nono-cli/src/platform.rs:146-169                                                                    | correctness (registry)    | **fix** — `first.eq_ignore_ascii_case(name)` for case-insensitive name match; regression test fixture                                                                      | platform.rs correctness    | TBD        |
| IN-01-P43  | 43-REVIEW.md | crates/nono-cli/src/pack_update_hint.rs:263-274                                                            | atomic-write              | **fix** (D-44-B5) — mirror `package::write_lockfile:367-379` tmp+rename                                                                                                   | pack_update_hint UX        | TBD        |
| IN-02-P43  | 43-REVIEW.md | crates/nono-cli/src/pack_update_hint.rs:183-218                                                            | detached JoinHandle       | **accept-as-documented** (D-44-B5) — explanatory comment at line 185                                                                                                       | pack_update_hint UX        | TBD        |
| IN-03-P43  | 43-REVIEW.md | crates/nono-cli/src/package_cmd.rs:341-346, 580-585                                                        | defense-in-depth          | **fix** — add `parts[0].is_empty() || parts[1].is_empty()` to length check; warning diagnostic                                                                             | misc INFO drain            | TBD        |
| IN-04-P43  | 43-REVIEW.md | crates/nono-cli/src/package_cmd.rs:629-633                                                                 | readability               | **fix** — 2-3 line comment above the double-evaluation in `run_outdated` explaining the asymmetry                                                                          | misc INFO drain            | TBD        |
| IN-05-P43  | 43-REVIEW.md | crates/nono-cli/src/platform.rs:153                                                                        | cosmetic                  | **accept-as-documented** (D-44-B5) — comment noting multi-space collapse is intentional given tab-aligned `reg query` output                                                | platform.rs correctness    | TBD        |

**Disposition counts:** fix = 23 ; doc-only = 1 ; verify-and-fix-if-needed = 1 ; defer = 1 ; accept-as-documented = 2 . Total = 28. Zero silent ignores.

<tasks>

<task type="auto">
  <name>Task 1 — Widen tests/common/test_env.rs gate + add lock_env mirror (PATTERNS.md friction point)</name>
  <files>crates/nono-cli/tests/common/test_env.rs</files>
  <read_first>
    1. crates/nono-cli/tests/common/test_env.rs (whole file — currently `#![cfg(target_os = "windows")]` at line 19; orphan-on-Linux note at lines 12-17)
    2. crates/nono-cli/src/test_env.rs lines 1-17 (canonical `lock_env()` primitive)
    3. .planning/phases/44-review-polish-test-hygiene-drain/44-PATTERNS.md § Pattern 1 (critical implementation note at bottom)
    4. .planning/phases/37-linux-resl-backends-pkgs-auto-pull/37-REVIEW.md lines 49-57 (WR-03 fix wording)
    5. CLAUDE.md § Coding Standards bullet "Environment variables in tests"
  </read_first>
  <action>
    Modify crates/nono-cli/tests/common/test_env.rs:

    (1) Widen the gate at line 19 from `#![cfg(target_os = "windows")]` to:
    `#![cfg(any(target_os = "windows", target_os = "linux"))]`

    (2) Update the orphan-on-Linux comment block at lines 12-17 to read:
    `//! Phase 44 WR-03/WR-04/IN-01 P37 (REQ-REVIEW-FU-01 D-44-E6): the gate`
    `//! is widened to include Linux so tests/auto_pull_e2e_linux.rs can use`
    `//! the canonical Drop-restore guard instead of a file-local EnvGuard.`
    `//! macOS does not yet host an integration-test consumer of this mirror;`
    `//! if one is added, widen the gate further.`

    (3) Add a lock_env mirror at the end of the file (after the `Drop` impl):

        /// Process-global lock for tests that mutate environment variables.
        ///
        /// Tests in this integration-test compilation unit MUST call
        /// let _lock = lock_env(); at the top of every test function that
        /// constructs an EnvVarGuard. EnvVarGuard's Drop-restore is necessary
        /// but not sufficient: it restores state at test end, but does not
        /// prevent a sibling test on a parallel thread from observing the
        /// mutated state DURING this test's execution. lock_env serializes
        /// the parallel runner across env-var-mutating tests.
        ///
        /// Mirrors crates/nono-cli/src/test_env.rs::lock_env which is not
        /// visible from integration tests (binary-crate cfg(test) modules
        /// do not export across the crate boundary).
        pub static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

        pub fn lock_env() -> std::sync::MutexGuard<'static, ()> {
            match ENV_LOCK.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            }
        }

    (4) Do NOT add `#[allow(dead_code)]` on lock_env — per D-44-E5 + CLAUDE.md "Lazy use of dead code", Task 2 wires real consumers in auto_pull_e2e_linux.rs so the function is exercised. Land this commit atomically with Task 2.

    Commit: fold into the chore(44-01): test thread-safety commit alongside Task 2.
  </action>
  <verify>
    <automated>grep -n 'pub fn lock_env' crates/nono-cli/tests/common/test_env.rs ; grep -n 'cfg(any(target_os' crates/nono-cli/tests/common/test_env.rs</automated>
  </verify>
  <acceptance_criteria>
    - grep -c 'cfg(any(target_os = "windows", target_os = "linux"))' crates/nono-cli/tests/common/test_env.rs returns 1
    - grep -c 'pub fn lock_env' crates/nono-cli/tests/common/test_env.rs returns 1
    - cargo build --tests -p nono-cli --target x86_64-unknown-linux-gnu succeeds (when cross-toolchain available; else mark PARTIAL)
    - No `#[allow(dead_code)]` anywhere in the file
  </acceptance_criteria>
  <done>Gate widened to any(windows, linux); lock_env mirror present; file compiles on both platforms (verified by Task 2 once consumers wired).</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2 — test thread-safety: WR-03 + WR-04 + IN-01 + IN-05 P37 (auto_pull_e2e_linux.rs)</name>
  <files>
    crates/nono-cli/tests/auto_pull_e2e_linux.rs
    .github/workflows/phase-37-linux-resl.yml
  </files>
  <behavior>
    - Every test function in auto_pull_e2e_linux.rs acquires lock_env BEFORE constructing any env-var guard
    - Every test that sets NONO_TEST_HOME ALSO sets XDG_CONFIG_HOME to the same tempdir (WR-04)
    - File-local EnvGuard struct removed entirely (no dead-code)
    - Workflow no longer uses `-- --test-threads=1`
    - Tests pass under plain `cargo test -p nono-cli --test auto_pull_e2e_linux` on a Linux host
  </behavior>
  <read_first>
    1. crates/nono-cli/tests/auto_pull_e2e_linux.rs lines 1-100 (file-local EnvGuard 29-61, 5 test functions referenced)
    2. crates/nono-cli/tests/common/test_env.rs (post-Task-1)
    3. 37-REVIEW.md lines 49-65 (WR-03 + WR-04 — exact wording at 55-57: `mod common; use common::test_env::lock_env;`)
    4. 37-REVIEW.md lines 117-118 (IN-01 tied to WR-03)
    5. 37-REVIEW.md lines 129-130 (IN-05 req_count widening)
    6. .github/workflows/phase-37-linux-resl.yml lines 290-300 (current `--test-threads=1` site)
    7. CLAUDE.md § "Environment variables in tests"
  </read_first>
  <action>
    (1) Add module + import at top of auto_pull_e2e_linux.rs (after the cfg attribute):
        mod common;
        use common::test_env::{EnvVarGuard, lock_env};

    (2) DELETE the file-local EnvGuard struct at lines 29-61 entirely. No `#[allow(dead_code)]`.

    (3) For each of the 5 test functions (at lines 218, 280, 329, 391-465, 492 — confirm by grep), replace the existing pattern with:

        #[test]
        fn <existing_name>() {
            let _lock = lock_env();
            let tempdir = tempfile::tempdir().unwrap();
            let tempdir_str = tempdir.path().to_str().unwrap();
            let _env = EnvVarGuard::set_all(&[
                ("NONO_TEST_HOME", tempdir_str),
                ("XDG_CONFIG_HOME", tempdir_str),   // WR-04 P37 pin
                // ... preserve any other env vars the existing test sets ...
            ]);
            // ... rest of test body unchanged ...
        }

    Cross-reference each test body for its env-var set before editing.

    (4) WR-04 sibling tests at 218, 280, 329, 492: same XDG_CONFIG_HOME pin.

    (5) IN-05 — `auto_pull_unknown_name_fails_closed` (line 313-316): widen `req_count <= 2` to `req_count <= 4` and add a comment block above the assertion documenting the expected request set ("IN-05 P37 D-44-B5: widened from <=2 to <=4 to absorb harmless retry growth; expected requests = ...").

    (6) Drop `--test-threads=1` from .github/workflows/phase-37-linux-resl.yml:296. The command becomes:
        cargo test -p nono-cli --test auto_pull_e2e_linux --release -- --nocapture

    (7) DO NOT modify the test bodies beyond env-guard substitution + IN-05 widening + XDG_CONFIG_HOME pin. Behavioral assertions stay byte-identical.

    Commit message (with DCO sign-off per CLAUDE.md):

      chore(44-01): test thread-safety in auto_pull_e2e_linux

      WR-03 + WR-04 + IN-01 + IN-05 P37: replace file-local EnvGuard with
      canonical EnvVarGuard from tests/common/test_env.rs + lock_env from the
      same mirror. Pin XDG_CONFIG_HOME alongside NONO_TEST_HOME in all 5 tests
      so resolve_user_config_dir is forced through the tempdir branch. Drop
      --test-threads=1 belt-and-suspenders from the workflow now that the
      cross-test mutex is the load-bearing isolator.

      PATTERNS.md friction point: widen tests/common/test_env.rs gate from
      windows-only to any(windows, linux) and add lock_env() mirror.

      Closes 37-REVIEW.md WR-03, WR-04, IN-01, IN-05.

      Signed-off-by: <Name> <email>
  </action>
  <verify>
    <automated>grep -c 'EnvGuard' crates/nono-cli/tests/auto_pull_e2e_linux.rs ; grep -c 'lock_env' crates/nono-cli/tests/auto_pull_e2e_linux.rs ; grep -c 'XDG_CONFIG_HOME' crates/nono-cli/tests/auto_pull_e2e_linux.rs ; grep -v '^#' .github/workflows/phase-37-linux-resl.yml | grep -c 'test-threads=1'</automated>
  </verify>
  <acceptance_criteria>
    - On a Linux host (or cross-target if available): cargo test -p nono-cli --test auto_pull_e2e_linux --release -- --nocapture exits 0; else mark PARTIAL per cross-target-verify-checklist
    - grep -c 'EnvGuard' crates/nono-cli/tests/auto_pull_e2e_linux.rs returns 0 (file-local struct deleted)
    - grep -c 'lock_env' crates/nono-cli/tests/auto_pull_e2e_linux.rs returns at-least 5
    - grep -v '^#' .github/workflows/phase-37-linux-resl.yml | grep -c 'test-threads=1' returns 0
    - grep -c 'XDG_CONFIG_HOME' crates/nono-cli/tests/auto_pull_e2e_linux.rs returns at-least 5
    - Plan disposition table rows WR-03/WR-04/IN-01/IN-05 marked with commit ref
  </acceptance_criteria>
  <done>All 5 tests use canonical lock_env + EnvVarGuard; XDG_CONFIG_HOME pinned; --test-threads=1 dropped; EnvGuard struct removed.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3 — CI hygiene: WR-01 + WR-08 + WR-10 P37 (awk multi-line + workflow env injection)</name>
  <files>
    .github/scripts/check-cli-doc-flags.sh
    .github/workflows/phase-37-linux-resl.yml
  </files>
  <behavior>
    - check-cli-doc-flags.sh correctly accumulates multi-line `#[arg(...)]` blocks (WR-01)
    - The script skips fields whose accumulated attr contains `hide = true` (WR-10)
    - Script's pipeline emits `no-auto-pull` for ProfileResolverArgs::no_auto_pull (proves WR-01 fix)
    - Script's pipeline emits `allow` for SandboxArgs::allow (proves WR-01 unblocks pre-existing multi-line flags)
    - CI workflow line 135 uses env injection instead of direct `${{ github.workspace }}` (WR-08)
  </behavior>
  <read_first>
    1. .github/scripts/check-cli-doc-flags.sh whole file (awk pipeline at lines 18-53)
    2. .planning/phases/44-review-polish-test-hygiene-drain/44-PATTERNS.md § "check-cli-doc-flags.sh" target retrofit shape
    3. 37-REVIEW.md lines 29-38 (WR-01 + empirical evidence)
    4. 37-REVIEW.md lines 91-97 (WR-08 fix)
    5. 37-REVIEW.md lines 107-113 (WR-10 fix)
    6. crates/nono-cli/src/cli.rs (read SandboxArgs::allow + ProfileResolverArgs::no_auto_pull + --dangerous-force-wfp-ready definition at line 1773)
  </read_first>
  <action>
    Part A — .github/scripts/check-cli-doc-flags.sh (WR-01 + WR-10):

    Replace the existing single-line awk rule at line 24:
        /#\[arg\(/ && /long/ { attr = $0; next }
    with a multi-line accumulator that runs through `)]`:
        # Accumulate multi-line #[arg(...)] blocks until closing )]
        /#\[arg\(/ {
            attr = $0
            if (attr ~ /\)\]/) { in_arg = 0 } else { in_arg = 1 }
            next
        }
        in_arg {
            attr = attr " " $0
            if ($0 ~ /\)\]/) { in_arg = 0 }
            next
        }

    Then at the field-line rule (the `^[[:space:]]*pub[[:space:]]+[a-zA-Z0-9_]+:` block at lines 64-67), insert the hide-skip BEFORE the existing long="..." extraction:
        /^[[:space:]]*pub[[:space:]]+[a-zA-Z0-9_]+:/ {
            if (attr == "") { next }
            # WR-10 P37: skip fields with hide = true so hidden flags are excluded.
            if (attr ~ /hide[[:space:]]*=[[:space:]]*true/) { attr = ""; next }
            # ... existing long="..." extraction unchanged ...
        }

    Preserve any existing logic for `long = "..."` extraction, the field-name fallback `gsub(/_/, "-", field)`, and the print statement. Verify exact line numbers in the existing pipeline by reading the file first — the line ranges in 37-REVIEW.md and PATTERNS.md are approximate; the actual edit is structural.

    Part B — .github/workflows/phase-37-linux-resl.yml (WR-08):

    At line 135 (the step that uses `${{ github.workspace }}` directly inside machinectl shell command), introduce the env block:

        - name: Run RESL-NIX integration tests under systemd user session
          env:
            WORKSPACE: ${{ github.workspace }}
          run: |
            sudo machinectl shell ${USER}@.host /usr/bin/env bash -c \
              "cd \"$WORKSPACE\" && cargo test -p nono-cli --test resl_nix_linux --test resl_nix_async_signal_safety --release -- --nocapture"

    The exact existing command must be preserved byte-for-byte except for the workspace substitution and the new env block. Read the file first.

    Commit message:

      chore(44-01): CI hygiene — doc-check parser + workflow env injection

      WR-01 + WR-08 + WR-10 P37 (37-REVIEW.md):

      - check-cli-doc-flags.sh: accumulate multi-line #[arg(...)] blocks
        until closing )] so multi-line attributes (like
        ProfileResolverArgs::no_auto_pull and SandboxArgs::allow) are no
        longer silently exempted from doc-parity validation. Restores ~30
        pre-existing multi-line flags to coverage.

      - check-cli-doc-flags.sh: skip fields with hide = true in accumulated
        attr (e.g. --dangerous-force-wfp-ready) so the script does not
        exit non-zero on intentionally-hidden flags.

      - phase-37-linux-resl.yml: replace direct ${{ github.workspace }}
        injection with env: WORKSPACE block per GitHub's Actions hardening doc.

      Closes 37-REVIEW.md WR-01, WR-08, WR-10.

      Signed-off-by: <Name> <email>
  </action>
  <verify>
    <automated>grep -c 'in_arg' .github/scripts/check-cli-doc-flags.sh ; grep -c 'hide' .github/scripts/check-cli-doc-flags.sh ; grep -v '^#' .github/workflows/phase-37-linux-resl.yml | grep -c 'WORKSPACE'</automated>
  </verify>
  <acceptance_criteria>
    - grep -c 'in_arg' .github/scripts/check-cli-doc-flags.sh returns at-least 2 (accumulator state)
    - grep -c 'hide.*=.*true' .github/scripts/check-cli-doc-flags.sh returns at-least 1
    - bash .github/scripts/check-cli-doc-flags.sh exits 0 against current docs
    - bash -x .github/scripts/check-cli-doc-flags.sh shows `no-auto-pull` and `allow` being emitted (manual cross-check)
    - grep -v '^#' .github/workflows/phase-37-linux-resl.yml | grep -c 'WORKSPACE: ' returns 1
    - grep -v '^#' .github/workflows/phase-37-linux-resl.yml | grep -c '\$WORKSPACE' returns at-least 1
    - Plan disposition table rows WR-01/WR-08/WR-10 marked with commit ref
  </acceptance_criteria>
  <done>Multi-line arg blocks parse; hide=true flags skipped; workflow uses env-var injection; script passes on current source tree.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 4 — platform.rs correctness: WR-02 P37 + WR-02/WR-04/WR-06 P43 + IN-05/IN-06 (CGROUP_V2_HINT + REG_DWORD + Ord symmetry + registry case + cgroup summary)</name>
  <files>
    crates/nono-cli/src/platform.rs
    crates/nono-cli/src/exec_strategy/supervisor_linux.rs
    crates/nono/src/error.rs
  </files>
  <behavior>
    - crates/nono/src/error.rs exposes `pub const CGROUP_V2_HINT: &str = "cgroup v2 required; boot with systemd.unified_cgroup_hierarchy=1 or cgroup_no_v1=all"` at module level
    - All 6 sites in supervisor_linux.rs (891, 901, 910, 981, 993, 997) reference the const (no literal duplication)
    - parse_windows_registry_value matches names case-insensitively (WR-06)
    - parse_windows_registry_value returns None on malformed REG_DWORD (WR-02 P43)
    - compare_versions is Ord-symmetric on non-numeric segments (WR-04 P43)
    - supervisor_linux.rs has a top-of-cgroup-module doc comment enumerating the 5 sites (IN-06)
    - In-file `#[cfg(test)] mod tests` gains 3 new regression tests
  </behavior>
  <read_first>
    1. crates/nono-cli/src/platform.rs whole file (146-169 WR-02/WR-06, 583-597 WR-04, existing mod tests at 599+)
    2. crates/nono-cli/src/exec_strategy/supervisor_linux.rs lines 880-1010 (6 hint sites + cgroup mod structure)
    3. crates/nono/src/error.rs lines 410-440 (UnsupportedKernelFeature + LOCKED_HINT in test mod at 425-426)
    4. 44-PATTERNS.md § "platform.rs:146-169" + "platform.rs:583-597" + "supervisor_linux.rs" target retrofits
    5. 43-REVIEW.md lines 111-146 (WR-02 P43), 196-233 (WR-04 P43), 289-320 (WR-06 P43)
    6. 37-REVIEW.md lines 41-47 (WR-02 P37) + 132-135 (IN-06 P37)
  </read_first>
  <action>
    Part A — Promote CGROUP_V2_HINT (WR-02 P37):

    In crates/nono/src/error.rs, ADD at module level (above UnsupportedKernelFeature):

        /// LOCKED — keep in sync with all cgroup_v2-detecting call sites in
        /// crates/nono-cli/src/exec_strategy/supervisor_linux.rs. The boot-flag
        /// hint must remain stable for REQ-RESL-NIX-01 acceptance #5 — FFI
        /// consumers grep this string from nono_last_error() Display output.
        ///
        /// Phase 44 WR-02 P37 (REQ-REVIEW-FU-01 D-44-A4): promoted from the
        /// test-mod-only LOCKED_HINT after duplication accreted across 6
        /// supervisor_linux.rs call sites.
        pub const CGROUP_V2_HINT: &str =
            "cgroup v2 required; boot with systemd.unified_cgroup_hierarchy=1 or cgroup_no_v1=all";

    Update the test-module local const (line 425-426) to reference the new module-level const:
        const LOCKED_HINT: &str = super::CGROUP_V2_HINT;

    Part B — Replace 6 sites in supervisor_linux.rs:

    At each of lines 891, 901, 910, 981, 993, 997, replace the duplicated literal:
        hint: "cgroup v2 required; boot with systemd.unified_cgroup_hierarchy=1 or cgroup_no_v1=all".into(),
    with:
        hint: nono::error::CGROUP_V2_HINT.into(),
    (verify exact import path — add `use nono::error::CGROUP_V2_HINT;` near top of supervisor_linux.rs once, then reference as `CGROUP_V2_HINT.into()` at each site).

    Part C — IN-06 P37 cgroup summary:

    Add a module-doc comment at the top of the `cgroup` submodule in supervisor_linux.rs (around line 888) enumerating the 5 detection sites:

        /// Detection sites for cgroup-v2 availability (Phase 44 IN-06 P37):
        ///
        /// 1. line 891  — initial sandbox setup fail-fast
        /// 2. line 901  — resource-limit application
        /// 3. line 910  — capability-grant cgroup-v2 dependency
        /// 4. (intentionally kept as UnsupportedPlatform — different error class)
        /// 5a. line 981 — supervisor IPC handler
        /// 5b. line 993 — supervisor cleanup
        /// 5c. line 997 — supervisor teardown
        ///
        /// All 6 cgroup-v2 sites use the LOCKED CGROUP_V2_HINT const from
        /// nono::error so the boot-flag hint stays stable for FFI consumers.
        mod cgroup {

    Line numbers are approximate; executor adjusts to match actual sites.

    Part D — parse_windows_registry_value (WR-02 + WR-06 P43):

    Replace the function body verbatim per 43-REVIEW.md:138-146 + 312-316:

        fn parse_windows_registry_value(output: &str, name: &str) -> Option<String> {
            for line in output.lines() {
                let mut parts = line.split_whitespace();
                let first = parts.next()?;
                if !first.eq_ignore_ascii_case(name) {       // WR-06 P43
                    continue;
                }
                let kind = parts.next()?;
                let value = parts.collect::<Vec<_>>().join(" ");
                if !value.is_empty() {
                    if kind == "REG_DWORD" {
                        if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
                            return u64::from_str_radix(hex, 16).ok().map(|n| n.to_string());
                        }
                        // REG_DWORD without 0x prefix is malformed — bail rather than
                        // returning a string that looks like a number but isn't.
                        return None;                          // WR-02 P43
                    }
                    return Some(value);
                }
            }
            None
        }

    Part E — compare_versions (WR-04 P43):

    Replace the non-numeric arm verbatim per 43-REVIEW.md:223-233:

        let ordering = match (left_part.parse::<u64>(), right_part.parse::<u64>()) {
            (Ok(left_num), Ok(right_num)) => left_num.cmp(&right_num),
            // Both unparseable: lexicographic fallback (Phase 44 WR-04 P43 Ord
            // antisymmetry fix). Mixed numeric/non-numeric sorts non-numeric
            // LESS so "alpha" < "1" for fail-closed predicate semantics.
            (Err(_), Err(_)) => left_part.cmp(right_part),
            (Ok(_), Err(_)) => Ordering::Greater,
            (Err(_), Ok(_)) => Ordering::Less,
        };

    Part F — Add 3 regression tests to `#[cfg(test)] mod tests` in platform.rs:

        #[test]
        fn parse_windows_registry_value_accepts_case_mismatch() {
            // Phase 44 WR-06 P43: registry value names case-insensitive.
            let output = "    EditionId    REG_SZ    Professional\n";
            assert_eq!(
                parse_windows_registry_value(output, "EditionID"),
                Some("Professional".to_string()),
            );
        }

        #[test]
        fn parse_windows_registry_value_rejects_malformed_dword() {
            // Phase 44 WR-02 P43: malformed REG_DWORD returns None, not raw garbage.
            let output = "    UBR    REG_DWORD    0xZZZ\n";
            assert_eq!(parse_windows_registry_value(output, "UBR"), None);
            let output2 = "    UBR    REG_DWORD    \n";
            assert_eq!(parse_windows_registry_value(output2, "UBR"), None);
        }

        #[test]
        fn compare_versions_is_symmetric_on_non_numeric_segments() {
            // Phase 44 WR-04 P43: Ord antisymmetry must hold on non-numeric inputs.
            use std::cmp::Ordering;
            assert_eq!(compare_versions("a", "b"), Ordering::Less);
            assert_eq!(compare_versions("b", "a"), Ordering::Greater);
            assert_eq!(compare_versions("1", "a"), Ordering::Greater);
            assert_eq!(compare_versions("a", "1"), Ordering::Less);
            assert_eq!(compare_versions("alpha", "alpha"), Ordering::Equal);
        }

    Part G — IN-05 P43 cosmetic comment (multi-space collapse):

    At platform.rs:153 inside parse_windows_registry_value, add an inline comment above the collect+join site:
        // IN-05 P43 (D-44-B5 accept-as-documented): multi-space collapse is
        // intentional given tab-aligned `reg query` output — cosmetic-only.
        let value = parts.collect::<Vec<_>>().join(" ");

    Commit message:

      chore(44-01): platform.rs correctness + CGROUP_V2_HINT dedup

      WR-02 + WR-04 + WR-06 P43 + WR-02 + IN-05 + IN-06 P37 (44-CONTEXT.md
      D-44-A4 group "platform.rs correctness"):

      - WR-02 P37: promote LOCKED_HINT to pub const CGROUP_V2_HINT in
        nono::error; reference at all 6 supervisor_linux.rs sites.

      - WR-02 P43: parse_windows_registry_value returns None on malformed
        REG_DWORD (was returning raw "0xZZZ" strings).

      - WR-04 P43: compare_versions non-numeric arm uses symmetric
        lexicographic comparison; antisymmetry regression test added.

      - WR-06 P43: parse_windows_registry_value uses eq_ignore_ascii_case
        for value-name match. Regression test fixture with mixed case.

      - IN-06 P37: module-doc comment at top of cgroup submodule
        enumerates the 5 detection sites + site-3→5a jump.

      - IN-05 P43: inline comment on intentional multi-space collapse.

      Closes 37-REVIEW.md WR-02, IN-05, IN-06 and 43-REVIEW.md WR-02, WR-04, WR-06.

      Signed-off-by: <Name> <email>
  </action>
  <verify>
    <automated>cargo test -p nono-cli --lib platform 2>&amp;1 | tail -15 ; grep -c 'pub const CGROUP_V2_HINT' crates/nono/src/error.rs ; grep -c 'CGROUP_V2_HINT' crates/nono-cli/src/exec_strategy/supervisor_linux.rs ; grep -c 'eq_ignore_ascii_case' crates/nono-cli/src/platform.rs</automated>
  </verify>
  <acceptance_criteria>
    - grep -c 'pub const CGROUP_V2_HINT' crates/nono/src/error.rs returns 1
    - grep -v '^#' crates/nono-cli/src/exec_strategy/supervisor_linux.rs | grep -c 'cgroup v2 required' returns 0 (literal de-duplicated)
    - grep -c 'CGROUP_V2_HINT' crates/nono-cli/src/exec_strategy/supervisor_linux.rs returns at-least 6
    - grep -c 'eq_ignore_ascii_case' crates/nono-cli/src/platform.rs returns at-least 1
    - cargo test -p nono-cli --lib platform exits 0 (3 new tests pass)
    - cargo build --workspace exits 0 on Windows host
    - Cross-target clippy gates (Linux + macOS) exit 0 per cross-target-verify-checklist (or PARTIAL with explicit live-CI deferral)
    - Plan disposition table rows WR-02-P37/IN-05-P43/IN-06-P37/WR-02-P43/WR-04-P43/WR-06-P43 marked with commit ref
  </acceptance_criteria>
  <done>CGROUP_V2_HINT is the single source of truth; parse_windows_registry_value handles case-mismatch + malformed REG_DWORD; compare_versions is Ord-symmetric; 3 regression tests pin invariants.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 5 — pack_update_hint UX: WR-03 + WR-05 + IN-01 + IN-02 P43 (drop sync + semver + atomic save + detached-handle doc)</name>
  <files>
    crates/nono-cli/src/pack_update_hint.rs
    crates/nono-cli/src/sandbox_prepare.rs
  </files>
  <behavior>
    - refresh_synchronous function and all callsites DELETED entirely (no #[allow(dead_code)]) — D-44-B2 option b
    - On stale entries, show_pack_update_hints always calls refresh_in_background regardless of cache-existed state
    - First-run users see hints on the 2nd nono run invocation (acceptable per D-44-B2 + CLAUDE.md "Zero startup latency")
    - is_newer strips pre-release/build-metadata before numeric parse; returns false when EITHER side is unparseable
    - save_state uses atomic tmp+rename write pattern mirroring package::write_lockfile:367-379
    - refresh_in_background has comment at line 185 documenting detached-handle accept-as-documented (IN-02)
    - sandbox_prepare.rs:108-112 callsite still calls show_pack_update_hints; signature compatible
  </behavior>
  <read_first>
    1. crates/nono-cli/src/pack_update_hint.rs whole file (show_pack_update_hints 80-110, refresh_synchronous 160-181, refresh_in_background 183-218, save_state 263-274, is_newer 290-304)
    2. crates/nono-cli/src/package.rs:367-379 (write_lockfile atomic pattern reference)
    3. crates/nono-cli/src/sandbox_prepare.rs:105-115 (callsite)
    4. 43-REVIEW.md lines 148-188 (WR-03), 237-287 (WR-05), 322-340 (IN-01 + IN-02)
    5. 44-PATTERNS.md § "pack_update_hint.rs" Analogs A-D
    6. crates/nono-cli/Cargo.toml:71 (semver = "1" workspace dep — available; the lightweight strip-and-parse closure is preferred per D-44-B2)
  </read_first>
  <action>
    Part A — Delete refresh_synchronous (WR-05 P43):

    (1) In show_pack_update_hints, DELETE the entire `if !cache_existed { refresh_synchronous(...) ... } else { ... refresh_in_background ... }` conditional. Replace with always-background pattern:

        if !stale.is_empty() {
            // Phase 44 WR-05 P43 (D-44-B2 option b): always background-refresh.
            // First-run users see no hint until the 2nd nono run — preferred
            // over up-to-5min synchronous stalls when the registry is
            // unreachable (CLAUDE.md § Performance: Zero startup latency).
            let shared = Arc::new(Mutex::new(state));
            refresh_in_background(stale, shared);
        }

    The post-refresh hint-collection loop (the inner `for (pack_ref, installed) in &stale` block that was inside the cache_existed=false branch) was only relevant for the synchronous path — DELETE it. First-run user sees no hint; second run picks up cache.

    (2) DELETE the refresh_synchronous function (lines 160-181) entirely. No #[allow(dead_code)].

    (3) If `cache_existed` local is now unused, remove it. If load_state previously distinguished "cache file missing" from "cache file empty" via a bool return, simplify to just returning the loaded state (default if missing), but do not change load_state's public signature unless callers are updated in this commit.

    Part B — is_newer semver fix (WR-03 P43):

    Replace is_newer (lines 290-304) verbatim per 43-REVIEW.md:172-188:

        fn is_newer(installed: &str, latest: &str) -> bool {
            let parse = |s: &str| -> Option<(u64, u64, u64)> {
                let s = s.strip_prefix('v').unwrap_or(s);
                // Strip pre-release / build metadata before splitting on '.'
                // (Phase 44 WR-03 P43 — was false-positiving on "1.2.3-beta"
                // against "1.2.3" due to "3-beta".parse::<u64>() failing).
                let core = s.split(['-', '+']).next().unwrap_or(s);
                let mut parts = core.splitn(3, '.');
                let major: u64 = parts.next()?.parse().ok()?;
                let minor: u64 = parts.next()?.parse().ok()?;
                let patch: u64 = parts.next()?.parse().ok()?;
                Some((major, minor, patch))
            };
            match (parse(installed), parse(latest)) {
                (Some(i), Some(l)) => l > i,
                // If either side is unparsable, suppress the hint rather than
                // false-positiving on pre-release installs.
                _ => false,
            }
        }

    Add 2 regression tests to in-file `#[cfg(test)] mod tests`:

        #[test]
        fn is_newer_suppresses_hint_on_prerelease_installed() {
            // Phase 44 WR-03 P43: "1.2.3-beta" must NOT trigger an update hint to "1.2.3".
            assert!(!is_newer("1.2.3-beta", "1.2.3"));
            assert!(!is_newer("2.0.0-rc1", "1.9.0"));
            assert!(!is_newer("1.2.3+build5", "1.2.3"));
        }

        #[test]
        fn is_newer_returns_true_on_genuine_upgrade() {
            assert!(is_newer("1.2.3", "1.2.4"));
            assert!(is_newer("v1.2.3", "v1.3.0"));
            assert!(!is_newer("1.2.4", "1.2.3"));
            assert!(!is_newer("1.2.3", "1.2.3"));
        }

    Part C — save_state atomic write (IN-01 P43):

    Replace save_state (lines 263-274) with:

        fn save_state(state: &PackHintsState) {
            let path = match state_file_path() {
                Some(p) => p,
                None => return,
            };
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(json) = serde_json::to_string_pretty(state) {
                // Phase 44 IN-01 P43 (D-44-B5): atomic tmp+rename, mirroring
                // crates/nono-cli/src/package.rs::write_lockfile:367-379.
                let tmp_path = path.with_extension("json.tmp");
                if std::fs::write(&tmp_path, json).is_ok() {
                    let _ = std::fs::rename(&tmp_path, &path);
                }
            }
        }

    Part D — refresh_in_background detached-handle comment (IN-02 P43):

    At line 185 immediately above `let _ = thread::spawn(...)`, add:

        // Phase 44 IN-02 P43 (D-44-B5 accept-as-documented): the JoinHandle is
        // intentionally detached. If nono exits before the HTTP request and
        // save_state complete, the network request is killed mid-flight and
        // the cache may not be updated. Worst case: more-aggressive registry
        // checking on the next run — acceptable per CONTEXT.md D-44-B5.
        let _ = thread::spawn(move || {

    Part E — sandbox_prepare.rs:108-112 callsite check:

    Confirm the callsite still compiles after Part A. No source change should be needed unless show_pack_update_hints's signature changed; if it did, update the callsite. Read the existing callsite first.

    Commit message:

      chore(44-01): pack_update_hint UX — drop sync + semver-aware is_newer + atomic save

      WR-03 + WR-05 + IN-01 + IN-02 P43:

      - WR-05: DELETE refresh_synchronous entirely (D-44-B2 option b).
        First-run users see hints on the 2nd nono run rather than blocking
        up to 5min on a dead registry. CLAUDE.md § Performance.

      - WR-03: is_newer strips semver pre-release/build-metadata before
        u64 parse; returns false on either-side parse failure. Closes the
        "1.2.3-beta" → "1.2.3" false-positive. Regression tests pin
        pre-release suppression + happy-path upgrade.

      - IN-01: save_state uses atomic tmp+rename, mirroring
        package::write_lockfile.

      - IN-02: refresh_in_background detached-handle accept-as-documented.

      Closes 43-REVIEW.md WR-03, WR-05, IN-01, IN-02.

      Signed-off-by: <Name> <email>
  </action>
  <verify>
    <automated>cargo test -p nono-cli --lib pack_update_hint 2>&amp;1 | tail -10 ; grep -c 'fn refresh_synchronous' crates/nono-cli/src/pack_update_hint.rs ; grep -c "split" crates/nono-cli/src/pack_update_hint.rs ; grep -c 'json.tmp' crates/nono-cli/src/pack_update_hint.rs</automated>
  </verify>
  <acceptance_criteria>
    - grep -c 'fn refresh_synchronous' crates/nono-cli/src/pack_update_hint.rs returns 0 (function fully deleted)
    - grep -c 'json.tmp' crates/nono-cli/src/pack_update_hint.rs returns at-least 1 (atomic tmp path)
    - grep -c 'is_newer_suppresses_hint_on_prerelease' crates/nono-cli/src/pack_update_hint.rs returns 1
    - cargo test -p nono-cli --lib pack_update_hint exits 0 (regression tests pass)
    - cargo build --workspace exits 0
    - grep -c 'allow(dead_code)' crates/nono-cli/src/pack_update_hint.rs unchanged (no new allow added)
    - Plan disposition table rows WR-03-P43/WR-05-P43/IN-01-P43/IN-02-P43 marked with commit ref
  </acceptance_criteria>
  <done>refresh_synchronous removed; is_newer pre-release-safe; save_state atomic; detached-handle documented; callsite still compiles.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 6 — feat(44-01): wire NONO_TRUST_OIDC_ISSUER production reader (WR-09 P37, D-44-B3)</name>
  <files>
    crates/nono/src/trust/signing.rs
    crates/nono/src/trust/mod.rs
    .github/workflows/phase-37-linux-resl.yml
  </files>
  <behavior>
    - crates/nono/src/trust/signing.rs exports `pub fn configured_oidc_issuer() -> Result<String>`
    - configured_oidc_issuer reads `NONO_TRUST_OIDC_ISSUER`; if set and non-empty, validates it parses as a URL via url::Url::parse and returns the value; if set but unparseable, returns NonoError::ConfigParse (fail-closed per CLAUDE.md § Fail Secure)
    - If env var unset or empty whitespace, returns the existing GITHUB_ACTIONS_OIDC_ISSUER constant value
    - At least 3 unit tests cover: env-set-and-valid; env-unset-fallback; env-set-but-malformed-rejected
    - The function is referenced from at least one signature-verification call site (e.g. trust_cmd.rs or a sibling verification path) so the workflow env var is no longer inert
    - The workflow's NONO_TRUST_OIDC_ISSUER setting at line 294 is now actually consumed; the comment at that line is updated to remove the "currently inert" note
  </behavior>
  <read_first>
    1. crates/nono/src/trust/signing.rs lines 1-160 (validate_oidc_issuer at 86-123 + const at ~134; the file-level doc comment at lines 19-26)
    2. crates/nono/src/trust/signing.rs lines 979-1090 (existing `mod tests` for test idiom)
    3. crates/nono/src/error.rs (NonoError::ConfigParse variant signature)
    4. crates/nono-cli/src/trust_cmd.rs (planner-side scan: grep for `validate_oidc_issuer` callsites — wire-up target)
    5. crates/nono/src/trust/mod.rs (re-exports — add configured_oidc_issuer if validate_oidc_issuer is re-exported)
    6. 37-REVIEW.md lines 99-105 (WR-09 — empirical evidence that NONO_TRUST_OIDC_ISSUER has zero matches in crates/)
    7. .github/workflows/phase-37-linux-resl.yml line 294 (env-var declaration site)
    8. 44-PATTERNS.md § "crates/nono/src/trust/signing.rs (NEW production reader)" target shape
    9. CLAUDE.md § Security Considerations (Fail Secure; Common Footguns #1)
  </read_first>
  <action>
    Part A — Add configured_oidc_issuer to crates/nono/src/trust/signing.rs:

    Insert after the existing GITHUB_ACTIONS_OIDC_ISSUER const (~line 134):

        /// Read the configured OIDC issuer pin, preferring NONO_TRUST_OIDC_ISSUER
        /// over the canonical GitHub Actions default. Returns the pin URL to
        /// use for [`validate_oidc_issuer`] callers. CLAUDE.md § Fail Secure:
        /// when the env var is set but unparseable as a URL, returns the
        /// parse error — the caller MUST refuse to publish/verify rather
        /// than silently falling back.
        ///
        /// REQ-PKGS-04 acceptance #4 (Phase 37 WR-09): when the CI workflow
        /// sets NONO_TRUST_OIDC_ISSUER=https://token.actions.githubusercontent.com,
        /// this reader returns that value and downstream validate_oidc_issuer
        /// enforces the pin against the GitHub token's iss claim.
        ///
        /// # Errors
        ///
        /// Returns NonoError::ConfigParse when NONO_TRUST_OIDC_ISSUER is set
        /// to a non-empty value that fails url::Url::parse. Whitespace-only
        /// values are treated as unset (falls back to default) — CLAUDE.md
        /// § Fail Secure on garbage input.
        pub fn configured_oidc_issuer() -> Result<String> {
            match std::env::var("NONO_TRUST_OIDC_ISSUER") {
                Ok(v) if !v.trim().is_empty() => {
                    // Eagerly validate that the env-var value is a parseable URL —
                    // fail-closed before any signature operation begins.
                    url::Url::parse(&v).map_err(|e| {
                        NonoError::ConfigParse(format!(
                            "NONO_TRUST_OIDC_ISSUER='{v}' is not a valid URL: {e}"
                        ))
                    })?;
                    Ok(v)
                }
                _ => Ok(GITHUB_ACTIONS_OIDC_ISSUER.to_string()),
            }
        }

    Part B — Add 3 unit tests to the existing `mod tests` in signing.rs:

    Use the canonical lock_env + EnvVarGuard pattern. NOTE: the crate-internal `mod test_env` in src/test_env.rs IS visible to this in-file test mod (same crate), so the existing imports apply directly. Import `crate::test_env::{lock_env, EnvVarGuard}` at the top of the test module if not already imported.

        #[test]
        fn configured_oidc_issuer_returns_env_when_set() {
            let _lock = crate::test_env::lock_env();
            let _g = crate::test_env::EnvVarGuard::set_all(&[(
                "NONO_TRUST_OIDC_ISSUER",
                "https://token.actions.githubusercontent.com",
            )]);
            assert_eq!(
                configured_oidc_issuer().unwrap(),
                "https://token.actions.githubusercontent.com"
            );
        }

        #[test]
        fn configured_oidc_issuer_falls_back_to_github_default_when_unset() {
            let _lock = crate::test_env::lock_env();
            // EnvVarGuard's Drop restore handles the case where the env var
            // was set by a sibling test; explicitly remove here to assert
            // the unset-branch path.
            let _g = crate::test_env::EnvVarGuard::set_all(&[]);
            std::env::remove_var("NONO_TRUST_OIDC_ISSUER");
            assert_eq!(
                configured_oidc_issuer().unwrap(),
                GITHUB_ACTIONS_OIDC_ISSUER
            );
        }

        #[test]
        fn configured_oidc_issuer_rejects_malformed_env_value() {
            let _lock = crate::test_env::lock_env();
            let _g = crate::test_env::EnvVarGuard::set_all(&[(
                "NONO_TRUST_OIDC_ISSUER",
                "not a valid url at all",
            )]);
            let err = configured_oidc_issuer().unwrap_err();
            assert!(
                matches!(err, NonoError::ConfigParse(_)),
                "expected ConfigParse, got {err:?}"
            );
        }

    Verify the exact path of `lock_env` + `EnvVarGuard` in src/test_env.rs first; if the visibility is `pub(crate)` instead of `pub`, the import `crate::test_env::*` works inside the library crate's test module.

    Part C — Re-export in crates/nono/src/trust/mod.rs:

    If `validate_oidc_issuer` is re-exported from trust/mod.rs, add `configured_oidc_issuer` to the same re-export line. If not, leave the function accessible via `nono::trust::signing::configured_oidc_issuer`.

    Part D — Wire-up call site:

    Identify the signature-verification call site (grep for `validate_oidc_issuer` callers in crates/nono-cli/src/trust_cmd.rs and crates/nono/src/). At the call site where the issuer pin is currently hardcoded to `GITHUB_ACTIONS_OIDC_ISSUER`, replace with `configured_oidc_issuer()?`. This makes the workflow's NONO_TRUST_OIDC_ISSUER setting actually take effect.

    If no current callsite exists yet (the env-var was inert prior to this commit), add the call where signature verification of GitHub-Actions-issued tokens is performed — the most likely site is wherever Phase 37 introduced the GitHub-Actions trust path. Acceptance gate per D-44-B3: "the env var is read; if set, asserts as the trusted OIDC issuer at signature verification time; if unset, falls back to current behavior".

    Part E — Update the workflow comment:

    In .github/workflows/phase-37-linux-resl.yml at line 294, update the comment block above the `NONO_TRUST_OIDC_ISSUER:` env declaration to reflect that the var is now consumed by `crates/nono/src/trust/signing.rs::configured_oidc_issuer`. Remove any "currently inert" or "TODO" language.

    Commit message (feat-class per D-44-B3):

      feat(44-01): wire NONO_TRUST_OIDC_ISSUER production reader

      WR-09 P37 (D-44-B3): the CI workflow has been setting
      NONO_TRUST_OIDC_ISSUER=https://token.actions.githubusercontent.com
      since Phase 37, but no production code read the value — the env-var
      was inert and the REQ-PKGS-04 acceptance #4 coverage claim on the
      workflow header was misleading.

      This commit adds configured_oidc_issuer() in crates/nono/src/trust/
      signing.rs as the canonical reader. It composes existing primitives
      (validate_oidc_issuer + GITHUB_ACTIONS_OIDC_ISSUER const). Fail-closed
      behavior:

      - env var set + parseable URL → returned and pinned at verification
      - env var set + unparseable → NonoError::ConfigParse (verification refused)
      - env var unset / whitespace-only → fall back to the const default

      Wire-up at the signature-verification call site replaces the
      previously hardcoded const with configured_oidc_issuer()?.

      3 unit tests pin the three branches.

      Closes 37-REVIEW.md WR-09.

      Signed-off-by: <Name> <email>
  </action>
  <verify>
    <automated>cargo test -p nono --lib trust::signing 2>&amp;1 | tail -15 ; grep -c 'fn configured_oidc_issuer' crates/nono/src/trust/signing.rs ; grep -rn 'NONO_TRUST_OIDC_ISSUER' crates/ | head -5</automated>
  </verify>
  <acceptance_criteria>
    - grep -c 'fn configured_oidc_issuer' crates/nono/src/trust/signing.rs returns 1
    - grep -rn 'NONO_TRUST_OIDC_ISSUER' crates/ shows at-least 2 matches (the reader + at least one consumer)
    - cargo test -p nono --lib trust::signing exits 0 (3 new tests pass)
    - The pre-fix grep `grep -r NONO_TRUST_OIDC_ISSUER crates/` returning "zero matches" (37-REVIEW.md line 102) is no longer true
    - Cross-target clippy (Linux + macOS) exits 0 per cross-target-verify-checklist (or PARTIAL)
    - Workflow comment at line 294 no longer claims the var is "currently inert" / contains no TODO marker
    - Plan disposition table row WR-09-P37 marked with the feat commit ref
  </acceptance_criteria>
  <done>configured_oidc_issuer reader exists; consumed at signature verification time; 3 unit tests cover env-set / env-unset / env-malformed branches; workflow env var no longer inert.</done>
</task>

<task type="auto">
  <name>Task 7 — docs(44-01): validate_restore_target TOCTOU doc + follow-up todo (WR-01 P43, D-44-B4)</name>
  <files>
    crates/nono/src/undo/snapshot.rs
    .planning/todos/pending/44-validate-restore-target-fd-relative-hardening.md
  </files>
  <behavior>
    - The doc comment immediately above `fn validate_restore_target` (currently at lines 588-594, above line 595) is EXTENDED (not replaced) to include the verbatim residual-race wording from 43-REVIEW.md:99-109
    - A new follow-up todo file exists at .planning/todos/pending/44-validate-restore-target-fd-relative-hardening.md capturing the fd-relative O_NOFOLLOW refactor scope across Linux + macOS + Windows
    - The function body of validate_restore_target itself is NOT modified (doc-only per D-44-B4)
  </behavior>
  <read_first>
    1. crates/nono/src/undo/snapshot.rs lines 580-690 (the existing doc comment above validate_restore_target + the function body for context)
    2. 43-REVIEW.md lines 74-109 (WR-01 P43 — exact suggested wording at 99-109)
    3. 44-PATTERNS.md § "crates/nono/src/undo/snapshot.rs:595-687 (WR-01 P43 — doc-only TOCTOU note)" target retrofit
    4. CLAUDE.md § Security Considerations (Path Handling — TOCTOU + canonicalization)
    5. .planning/todos/pending/41-10-linux-deny-overlap-regression.md (template shape for the new todo file)
  </read_first>
  <action>
    Part A — Extend the doc comment above validate_restore_target (do NOT replace existing prose; ADD new paragraph + reference to follow-up):

    The existing doc reads:
        /// Validate the live filesystem path that restore will write through.
        ///
        /// Manifest validation is lexical: it proves stored paths are under tracked
        /// roots, but it cannot see symlinks created after the snapshot. Restore
        /// runs outside the sandbox, so every existing parent component at or below
        /// the tracked root must be a real directory before create_dir_all,
        /// temp-file creation, rename, or chmod touches the path.

    Append a new paragraph (verbatim per 43-REVIEW.md:99-109):

        ///
        /// **Residual race window:** this check runs lexically against
        /// `symlink_metadata` and is followed by `create_dir_all` / atomic
        /// rename / `set_permissions` non-atomically. A local attacker with
        /// write access inside the tracked tree CAN race the validation by
        /// swapping a directory for a symlink between this function returning
        /// `Ok(())` and the write. Full closure requires `O_NOFOLLOW` and
        /// fd-relative ops; tracked as follow-up
        /// `.planning/todos/pending/44-validate-restore-target-fd-relative-hardening.md`.

    The function body itself is NOT modified.

    Part B — Create .planning/todos/pending/44-validate-restore-target-fd-relative-hardening.md:

        ---
        id: 44-validate-restore-target-fd-relative-hardening
        opened: 2026-05-20
        opened_by: Phase 44 Plan 44-01 (REQ-REVIEW-FU-01 docs WR-01 P43, D-44-B4)
        priority: medium
        category: security-hardening
        tags: [snapshot, restore, toctou, fd-relative, cross-platform]
        affects:
          - crates/nono/src/undo/snapshot.rs
        resolves_phase: null
        ---

        # validate_restore_target fd-relative TOCTOU hardening

        ## Context

        Phase 43 introduced `validate_restore_target` (snapshot.rs:595-687)
        as a per-file pre-write gate that rejects symlinked parent
        components before `create_dir_all` / `retrieve_to` / `set_permissions`.
        The function uses `fs::symlink_metadata` for component-wise check.

        Phase 43 code review (43-REVIEW.md WR-01) noted a residual TOCTOU
        race window between the lexical validation and the non-atomic
        write sequence: a local attacker with write access inside the
        tracked tree can swap a directory for a symlink between
        validation returning `Ok(())` and the write. Phase 44 D-44-B4
        chose doc-only fix + this follow-up todo.

        ## Scope

        Full closure requires `O_NOFOLLOW` + fd-relative ops (`openat`,
        `mkdirat`, `renameat`, `fchmodat`). This is a substantial
        cross-platform refactor:

        - **Linux**: nix crate exposes `openat`, `mkdirat`, `renameat`,
          `fchmodat`, `fchownat`. O_NOFOLLOW is a standard open flag.
          The library already depends on `nix` for other syscalls.
        - **macOS**: same nix surface (Darwin supports all the *at
          syscalls + O_NOFOLLOW). Spot-check `fchmodat` behavior under
          AT_SYMLINK_NOFOLLOW flag.
        - **Windows**: NO direct equivalent. NtCreateFile + REPARSE_GUARD,
          OR rejection of any symlinked target component at validation
          time + double-check via second symlink_metadata at write time
          (best-effort defense-in-depth). Closing the race on Windows
          may require a different architectural approach (e.g. requiring
          the restore target tree to be on a no-symlink filesystem).

        ## Acceptance Criteria

        1. validate_restore_target + the subsequent create_dir_all /
           retrieve_to / set_permissions sequence is refactored to use
           fd-relative ops on Linux + macOS such that the write happens
           through the SAME fd the validation gated. No TOCTOU window.
        2. On Windows, the residual race is either closed via NtCreateFile-
           based path, OR a documented defense-in-depth pattern (double-
           validation + best-effort symlink_metadata at write-time) is
           applied and the residual risk is documented.
        3. Cross-platform tests prove the gate holds under concurrent
           symlink-swap attempts (e.g. spawn an attacker thread that
           busy-loops swapping a path; validate the restore either
           succeeds atomically or fails closed — never writes through
           a symlink that was swapped in mid-flight).
        4. The "Residual race window" paragraph in the function doc
           comment is removed (or replaced with "Closed by fd-relative
           op refactor in Phase NN").

        ## Estimated Cost

        Substantial: ~2-3 weeks of focused work spread across Linux,
        macOS, Windows + new race-detection test infrastructure. A
        dedicated security-scoped phase is warranted. Target window:
        post-v2.6 (after the windows-squash merge in Phase 46 lands
        the baseline; revisit at v2.7 milestone planning).

        ## References

        - Phase 43 43-REVIEW.md WR-01 (the original finding + suggested doc)
        - Phase 44 44-CONTEXT.md D-44-B4 (the doc-only disposition + this todo)
        - CLAUDE.md § Path Handling (TOCTOU with symlinks + canonicalization)

    Commit message (docs-class per D-44-B4):

      docs(44-01): document validate_restore_target TOCTOU residual race

      WR-01 P43 (D-44-B4): per Phase 43 code review and Phase 44 user
      decision, extend the validate_restore_target doc comment to
      explicitly document the residual TOCTOU window between the lexical
      symlink_metadata check and the non-atomic create_dir_all /
      retrieve_to / set_permissions sequence. Full closure requires
      O_NOFOLLOW + fd-relative ops across Linux + macOS + Windows — a
      substantial cross-platform refactor scoped in the new follow-up
      todo at .planning/todos/pending/44-validate-restore-target-fd-
      relative-hardening.md.

      The function body itself is NOT modified — doc-only + breadcrumb.

      Closes 43-REVIEW.md WR-01.

      Signed-off-by: <Name> <email>
  </action>
  <verify>
    <automated>grep -c 'Residual race window' crates/nono/src/undo/snapshot.rs ; test -f .planning/todos/pending/44-validate-restore-target-fd-relative-hardening.md &amp;&amp; echo "todo file exists" || echo "MISSING"</automated>
  </verify>
  <acceptance_criteria>
    - grep -c 'Residual race window' crates/nono/src/undo/snapshot.rs returns at-least 1
    - The follow-up todo file exists at the documented path
    - The function body of validate_restore_target is byte-identical to before the commit (verify by git diff)
    - cargo build --workspace exits 0 (doc-only change cannot break the build)
    - Plan disposition table row WR-01-P43 marked with the docs commit ref
  </acceptance_criteria>
  <done>Doc comment extended; follow-up todo filed; function body untouched.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 8 — misc INFO drain: WR-05 + WR-06 + WR-07 P37 + IN-02 + IN-03 + IN-04 + IN-07 P37 + IN-03 + IN-04 P43</name>
  <files>
    crates/nono/src/trust/mod.rs
    crates/nono-cli/tests/resl_nix_linux.rs
    crates/nono-cli/src/session_commands.rs
    crates/nono-cli/src/session_commands_windows.rs
    crates/nono-cli/src/format_util.rs
    crates/nono-cli/src/diagnostic_formatter.rs
    crates/nono-cli/src/package_cmd.rs
    crates/nono-cli/src/cli.rs
    crates/nono-cli/src/main.rs
  </files>
  <behavior>
    - WR-05 P37: a unit test asserts `VerificationPolicy::default().verify_sct == true` so any future sigstore-verify minor bump that flips the default forces an audit
    - WR-06 P37: resl_nix_linux.rs:37-39 uses nix::unistd::access(W_OK)
    - WR-07 P37: resl_nix_linux.rs has a require_cgroup_v2!() macro that gates linux_no_warnings_on_resource_flags so the test SKIPs (not passes-vacuously) on non-cgroup-v2 hosts
    - IN-03 P37: format_bytes_short extracted to crates/nono-cli/src/format_util.rs (NEW); session_commands.rs + session_commands_windows.rs import from there
    - IN-07 P37: diagnostic_formatter.rs:25 doc comment extended to surface the grep contract used by auto_pull_e2e_linux.rs:362-365
    - IN-04 P37 (--no-auto-pull env hint): verified at runtime — if clap auto-renders the env hint, no source change; if not, prepend env name to help string
    - IN-03 P43: package_cmd.rs lockfile-key parser adds `|| parts[0].is_empty() || parts[1].is_empty()` to length check with warning diagnostic
    - IN-04 P43: run_outdated in package_cmd.rs gets a 2-3 line comment explaining the asymmetry between needs_attention and all-current branches
    - IN-02 P37 (test asset detached listener): planner-discretion DEFER (D-44-B5); add a one-line comment at auto_pull_e2e_linux.rs:334 documenting the intentional detached pattern
  </behavior>
  <read_first>
    1. crates/nono/src/trust/mod.rs (existing test module structure + how `VerificationPolicy::default()` is exposed)
    2. crates/nono/Cargo.toml (sigstore-verify 0.7.0 pin context)
    3. crates/nono-cli/tests/resl_nix_linux.rs (WR-06 site at 37-39 + WR-07 site at 212-253 + cgroup_v2_available() helper if it exists)
    4. crates/nono-cli/src/session_commands.rs:691-714 + session_commands_windows.rs:610-628 (the duplicated format_bytes_short)
    5. crates/nono-cli/src/diagnostic_formatter.rs:25-41 (the existing format_error_footer doc comment)
    6. crates/nono-cli/src/cli.rs:1484-1496 (--no-auto-pull doc-comment + #[arg(...)] with env = "NONO_NO_AUTO_PULL")
    7. crates/nono-cli/src/package_cmd.rs:341-346, 580-585, 629-633 (IN-03 + IN-04 P43 sites)
    8. 37-REVIEW.md lines 66-90 (WR-05/WR-06/WR-07) + lines 117-140 (IN-02 through IN-07)
    9. 43-REVIEW.md lines 343-378 (IN-03 P43 lockfile-key + IN-04 P43 run_outdated)
    10. crates/nono-cli/src/lib.rs or main.rs (find where format_util should be declared as a module)
  </read_first>
  <action>
    Part A — WR-05 P37 sigstore SCT default pin-test:

    Identify the right test home — likely crates/nono/src/trust/mod.rs (existing test module) or a sibling unit-test module that already imports `sigstore_verify::VerificationPolicy`. Add the test:

        #[test]
        fn verification_policy_default_enables_sct_verification() {
            // Phase 44 WR-05 P37: lock the sigstore-verify 0.7.0 verify_sct
            // default to TRUE. If any future minor bump flips this default,
            // this test fails and forces an audit — protects the trust posture
            // documented in crates/nono/Cargo.toml:48.
            let policy = sigstore_verify::types::VerificationPolicy::default();
            assert!(
                policy.verify_sct,
                "VerificationPolicy::default().verify_sct must remain true; \
                 sigstore-verify default flipped — audit before bumping further."
            );
        }

    Verify the exact type path (`sigstore_verify::types::VerificationPolicy` or `::VerificationPolicy` from the crate root); adjust the import based on the dependency's current public surface.

    Part B — WR-06 P37 — resl_nix_linux.rs:37-39:

    Replace `!std::fs::Permissions::readonly(...)` with:
        use nix::unistd::{access, AccessFlags};
        let writable = access(path, AccessFlags::W_OK).is_ok();
    Or, per PATTERNS.md, drop the gate entirely if redundant with sibling checks (planner-discretion). Pick one approach and document it inline.

    Part C — WR-07 P37 — linux_no_warnings_on_resource_flags Phase-16-stub guard:

    Add a macro at the top of resl_nix_linux.rs:

        macro_rules! require_cgroup_v2 {
            () => {
                if !cgroup_v2_available() {
                    eprintln!("SKIP: cgroup-v2 unavailable");
                    return;
                }
            };
        }

    Then at the top of `linux_no_warnings_on_resource_flags` (line 212+), insert:
        require_cgroup_v2!();

    Confirm `cgroup_v2_available()` is already defined in the file or in tests/common; if not, add a minimal helper that reads /sys/fs/cgroup/cgroup.controllers (presence = v2 host).

    Part D — IN-03 P37 — format_bytes_short dedup:

    Create crates/nono-cli/src/format_util.rs (NEW) with the moved function:

        //! Cross-platform formatting helpers extracted from session_commands /
        //! session_commands_windows. Phase 44 IN-03 P37 (REQ-REVIEW-FU-01).
        
        /// Format a byte count as a short human-readable string ("1.2 GiB",
        /// "512 MiB"). Used by `nono inspect` + `nono logs` output.
        pub fn format_bytes_short(bytes: u64) -> String {
            // ... copy the EXISTING implementation verbatim from session_commands.rs:691-714
            //     (the Unix copy is the source of truth; both copies are semantically
            //     equivalent per 37-REVIEW.md IN-03)
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            #[test]
            fn format_bytes_short_handles_unit_boundaries() {
                // Pin a few canonical values to prevent drift.
                assert_eq!(format_bytes_short(0), "0 B");
                assert_eq!(format_bytes_short(1024), "1 KiB");
                assert_eq!(format_bytes_short(1024 * 1024), "1 MiB");
                assert_eq!(format_bytes_short(1024 * 1024 * 1024), "1 GiB");
            }
        }

    Declare the module in crates/nono-cli/src/main.rs (or lib.rs if one exists): `mod format_util;` near the other top-level `mod` declarations.

    Replace session_commands.rs:691-714 and session_commands_windows.rs:610-628 with a single re-export OR an import at top: `use crate::format_util::format_bytes_short;` Then DELETE both file-local copies.

    Part E — IN-04 P37 — --no-auto-pull env hint verification:

    Run `cargo run -- run --help 2>&1 | grep -A2 no-auto-pull`. If the output already contains `[env: NONO_NO_AUTO_PULL=]`, NO source change needed (clap auto-renders). If it does NOT, edit the doc comment at crates/nono-cli/src/cli.rs:1484-1496 to prepend the env-var name:

        /// [env: NONO_NO_AUTO_PULL] Disable cargo-install-style auto-pull when
        /// --profile references a registry pack not yet installed locally.
        /// Falls back to the legacy "profile not found" error.

    Document the chosen path inline with a comment.

    Part F — IN-07 P37 — diagnostic_formatter doc grep contract:

    At crates/nono-cli/src/diagnostic_formatter.rs:25, extend the existing doc comment to surface the grep contract:

        /// Format the error footer for top-level CLI failures.
        ///
        /// # Grep contract
        ///
        /// The integration test at
        /// `crates/nono-cli/tests/auto_pull_e2e_linux.rs:362-365` greps the
        /// formatted stderr for the literal `--no-auto-pull`. Future
        /// refactors must keep that token present in this function's
        /// output for the "set" of suggested mitigations.

    Part G — IN-03 P43 — package_cmd lockfile-key empty-segment guard:

    At crates/nono-cli/src/package_cmd.rs:341-346 and 580-585, replace:
        if parts.len() != 2 {
    with:
        if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
            tracing::warn!("skipping malformed lockfile key: {}", key);
            continue;
        }
    Verify exact existing structure first.

    Part H — IN-04 P43 — run_outdated comment:

    At crates/nono-cli/src/package_cmd.rs:629-633, ABOVE the double-evaluation block, add:
        // Phase 44 IN-04 P43: the two passes intentionally distinguish
        // "all current" (no entries with status="current"-other-than) from
        // "all current OR unknown" (the broader case where some packs are
        // status="unknown" — typically untracked sibling packs). Behaviorally
        // correct; this comment exists so future readers don't try to collapse
        // the two passes into a single classifier without preserving the
        // distinction.

    Part I — IN-02 P37 — auto_pull_e2e_linux.rs:334 detached-listener comment:

    Add at line 334 (above the mock TCP server spawn):
        // Phase 44 IN-02 P37 (D-44-B5 defer): the listener thread is
        // intentionally not contacted; it provides a port-binding sentinel
        // that proves the test's auto-pull URL is reachable before the
        // production code path attempts a real fetch. Detached on purpose;
        // tempdir Drop cleans up at test end.

    Commit message:

      chore(44-01): misc INFO drain — sigstore SCT pin + format_bytes_short dedup + resl_nix_linux guards

      WR-05 + WR-06 + WR-07 P37 + IN-02 + IN-03 + IN-04 + IN-07 P37 + IN-03 + IN-04 P43:

      - WR-05 P37: pin-test VerificationPolicy::default().verify_sct == true
        so any future sigstore-verify minor bump that flips the default
        forces an audit.

      - WR-06 P37: resl_nix_linux.rs writable-check uses nix::unistd::access
        instead of !Permissions::readonly heuristic.

      - WR-07 P37: introduce require_cgroup_v2!() macro; gate
        linux_no_warnings_on_resource_flags so it skips (not passes
        vacuously) on cgroup-v1 hosts.

      - IN-03 P37: extract format_bytes_short to crates/nono-cli/src/
        format_util.rs (NEW); session_commands{,_windows}.rs import from
        the shared module; deduplicates ~24 lines.

      - IN-04 P37: --no-auto-pull help text verified to render NONO_NO_AUTO_PULL
        env hint (either via clap auto-render OR explicit doc-comment prepend).

      - IN-07 P37: diagnostic_formatter doc comment extends the grep
        contract surfaced by auto_pull_e2e_linux:362-365.

      - IN-02 P37: auto_pull_e2e_linux:334 detached-listener intentional
        behavior documented (D-44-B5 defer).

      - IN-03 P43: package_cmd lockfile-key parser rejects empty segments
        with a warning diagnostic.

      - IN-04 P43: run_outdated double-evaluation asymmetry documented
        with a 2-3 line comment.

      Closes 37-REVIEW.md WR-05, WR-06, WR-07, IN-02, IN-03, IN-04, IN-07
      and 43-REVIEW.md IN-03, IN-04.

      Signed-off-by: <Name> <email>
  </action>
  <verify>
    <automated>cargo test -p nono --lib trust 2>&amp;1 | tail -10 ; test -f crates/nono-cli/src/format_util.rs &amp;&amp; echo "format_util exists" ; grep -c 'require_cgroup_v2' crates/nono-cli/tests/resl_nix_linux.rs ; grep -c 'verification_policy_default_enables_sct' crates/nono/src/trust/mod.rs crates/nono/src/trust/signing.rs 2>/dev/null ; grep -c 'AccessFlags::W_OK' crates/nono-cli/tests/resl_nix_linux.rs</automated>
  </verify>
  <acceptance_criteria>
    - test -f crates/nono-cli/src/format_util.rs returns success
    - grep -c 'fn format_bytes_short' crates/nono-cli/src/session_commands.rs returns 0
    - grep -c 'fn format_bytes_short' crates/nono-cli/src/session_commands_windows.rs returns 0
    - grep -c 'require_cgroup_v2' crates/nono-cli/tests/resl_nix_linux.rs returns at-least 2 (macro def + call site)
    - grep -c 'AccessFlags::W_OK' crates/nono-cli/tests/resl_nix_linux.rs returns 1
    - grep -rc 'verification_policy_default_enables_sct' crates/nono/src/ returns 1
    - grep -c 'Grep contract' crates/nono-cli/src/diagnostic_formatter.rs returns 1
    - cargo test -p nono-cli --lib format_util exits 0 (the new module's unit test)
    - cargo build --workspace exits 0
    - Cross-target clippy (Linux + macOS) exits 0 per cross-target-verify-checklist (or PARTIAL)
    - Plan disposition table rows WR-05/WR-06/WR-07/IN-02/IN-03/IN-04/IN-07 P37 + IN-03/IN-04 P43 marked with commit ref
  </acceptance_criteria>
  <done>All remaining WARN + INFO findings cleared; format_bytes_short deduplicated; sigstore SCT pin-test locks the trust posture default.</done>
</task>

<task type="auto">
  <name>Task 9 — Cross-target clippy verification gate (D-44-E2)</name>
  <files>
    .planning/phases/44-review-polish-test-hygiene-drain/44-01-CLIPPY-CROSS-TARGET.md
  </files>
  <read_first>
    1. .planning/templates/cross-target-verify-checklist.md (the protocol — Decision Tree + PARTIAL Disposition + Anti-Patterns)
    2. CLAUDE.md § Coding Standards bullet "Cross-target clippy verification"
    3. 44-CONTEXT.md D-44-E2
    4. Memory `feedback_clippy_cross_target`
  </read_first>
  <action>
    Run the cross-target clippy gate for every commit in Plan 44-01 that touched a cfg-gated Unix file. Per D-44-E2, the in-scope commits are at minimum:

    - chore(44-01): test thread-safety (auto_pull_e2e_linux.rs is `#![cfg(target_os = "linux")]`)
    - chore(44-01): CI hygiene (no Unix-cfg touch; out of scope)
    - chore(44-01): platform.rs correctness (supervisor_linux.rs is `#[cfg(target_os = "linux")]`)
    - chore(44-01): pack_update_hint UX (no cfg touch unless callsite changes; out of scope)
    - feat(44-01): wire NONO_TRUST_OIDC_ISSUER (cross-platform; in scope per CLAUDE.md "any file under bindings/c or with cfg(unix)")
    - docs(44-01): validate_restore_target TOCTOU doc (doc-only; out of scope per checklist)
    - chore(44-01): misc INFO drain (resl_nix_linux.rs is Linux-gated; in scope)

    For each in-scope commit, on the dev host:

    (1) Attempt `cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` from the workspace root after the commit lands.
    (2) Attempt `cargo clippy --workspace --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` from the workspace root after the commit lands.
    (3) If either fails to LINK (missing toolchain `error: linker x86_64-linux-gnu-gcc not found` or equivalent), this is a PARTIAL disposition per the checklist § PARTIAL Disposition. Record the exact error.
    (4) If either reports clippy errors (warnings/lints), FIX before merging.

    Create .planning/phases/44-review-polish-test-hygiene-drain/44-01-CLIPPY-CROSS-TARGET.md documenting the run with this exact shape:

        # Phase 44 Plan 44-01 — Cross-target Clippy Verification Log
        
        Per CLAUDE.md § Coding Standards + .planning/templates/cross-target-verify-checklist.md.
        
        ## In-scope commits (Plan 44-01)
        
        | Commit | Linux clippy | macOS clippy | Notes |
        |--------|--------------|--------------|-------|
        | chore(44-01): test thread-safety @ <sha> | PASS / PARTIAL / FAIL | PASS / PARTIAL / FAIL | <linker error text if PARTIAL> |
        | chore(44-01): platform.rs correctness @ <sha> | ... | ... | ... |
        | feat(44-01): wire NONO_TRUST_OIDC_ISSUER @ <sha> | ... | ... | ... |
        | chore(44-01): misc INFO drain @ <sha> | ... | ... | ... |
        
        ## PARTIAL disposition (if any lane was SKIPPED)
        
        Per cross-target-verify-checklist.md § PARTIAL Disposition: if any
        commit's cross-target clippy was SKIPPED due to missing toolchain,
        the REQ-REVIEW-FU-01 verification status carries forward as
        `human_needed` (NOT `passed`) until the live GH Actions
        {Linux Clippy | macOS Clippy} lane on the head SHA reports green.
        
        > Cross-target clippy gate SKIPPED on Windows dev host due to
        > missing toolchain (x86_64-{unknown-linux-gnu | apple-darwin}).
        > The live GH Actions {Linux Clippy | macOS Clippy} lane on the
        > head SHA is the decisive signal per
        > .planning/templates/cross-target-verify-checklist.md. REQ marked
        > PARTIAL pending CI confirmation.
        
        ## Out-of-scope commits (no cfg-gated Unix touch)
        
        - chore(44-01): CI hygiene — touches .github/ only
        - chore(44-01): pack_update_hint UX — cross-platform, no cfg gate
        - docs(44-01): validate_restore_target — doc-only

    This is bookkeeping for the verifier in Phase 44 close — the table above DOES NOT replace running the gates; it records the result of running them. The actual gate commands must be run as part of this task and the table populated with their actual outcomes.

    If toolchain unavailable, mark the log as PARTIAL and defer to live CI. No commit needed for the bookkeeping file unless the executor wants to amend it into the final misc INFO drain commit; otherwise leave it as an uncommitted local artifact that 44-SUMMARY.md will reference.
  </action>
  <verify>
    <automated>test -f .planning/phases/44-review-polish-test-hygiene-drain/44-01-CLIPPY-CROSS-TARGET.md &amp;&amp; head -40 .planning/phases/44-review-polish-test-hygiene-drain/44-01-CLIPPY-CROSS-TARGET.md ; echo "---HOST CHECK---" ; rustup target list --installed</automated>
  </verify>
  <acceptance_criteria>
    - .planning/phases/44-review-polish-test-hygiene-drain/44-01-CLIPPY-CROSS-TARGET.md exists with one row per in-scope commit
    - Each row is one of {PASS, PARTIAL, FAIL}; FAIL must be empty (any FAIL must have been resolved before reaching this acceptance gate)
    - If any row is PARTIAL, the file contains the verbatim PARTIAL disposition prose from cross-target-verify-checklist.md § PARTIAL Disposition
    - If ALL rows are PASS, the file ends with a "Conclusion: REQ-REVIEW-FU-01 may be flipped to VERIFIED at codebase level by /gsd-verify-phase" line
    - Plan disposition for the entire REQ-REVIEW-FU-01 inherits the strongest non-PASS status from this log
  </acceptance_criteria>
  <done>Cross-target clippy log present; every cfg-gated-Unix commit has a verdict (PASS or PARTIAL); REQ-REVIEW-FU-01 verification posture documented for the verifier.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| CI runner env → nono-cli (`NONO_TRUST_OIDC_ISSUER` env var) | The CI workflow controls this env var; the production reader added in Task 6 trusts the URL parses but does not trust the URL identity (downstream `validate_oidc_issuer` enforces scheme+host+port equality against an explicit pin). Untrusted-string crosses here. |
| Local user filesystem → restore-write path (`validate_restore_target`) | Phase 43 introduced the per-file gate; Phase 44 doc-only update names the residual TOCTOU race (post-validation symlink swap). Local-attacker-with-tree-write-access threat model documented. |
| Windows registry `reg query` output → `parse_windows_registry_value` | Registry value names are case-insensitive on Windows but the parser was case-sensitive (WR-06 P43). Defense-in-depth fix: case-insensitive name match + strict REG_DWORD validation. |
| `git remote` upstream → sibling-repo URL derivation | NOT in this plan (Plan 44-02 owns sibling-repo work). |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-44-01 | Spoofing (S) | `configured_oidc_issuer()` reading `NONO_TRUST_OIDC_ISSUER` | mitigate | The reader rejects unparseable URLs via `url::Url::parse` (NonoError::ConfigParse); whitespace-only env values are treated as unset (fall back to canonical default); the value is consumed by `validate_oidc_issuer` which enforces URL-component-level scheme+host+port equality (CLAUDE.md § Common Footguns #1). Test `configured_oidc_issuer_rejects_malformed_env_value` pins the fail-closed branch. |
| T-44-02 | Tampering (T) | `validate_restore_target` TOCTOU window (WR-01 P43 doc-only fix) | accept (per D-44-B4) | Residual race window documented in the function doc comment; follow-up todo `.planning/todos/pending/44-validate-restore-target-fd-relative-hardening.md` scopes the full O_NOFOLLOW / openat / fd-relative refactor. The threat model accepts the residual risk for this phase because closing the race requires substantial cross-platform refactor (Linux nix `openat` + macOS `*at` syscalls + Windows NtCreateFile-or-equivalent); the threat is BOUNDED by requiring a local attacker with write access INSIDE the tracked tree (otherwise validation rejects the path lexically). |
| T-44-03 | Information disclosure (I) | `parse_windows_registry_value` returning raw `"0xZZZ"` strings on malformed REG_DWORD (WR-02 P43) | mitigate | Fixed: return `None` on malformed REG_DWORD so downstream `compare_versions` does not interpret garbage as a version number. Regression test `parse_windows_registry_value_rejects_malformed_dword` pins the None-return branch. No security-critical info disclosure was happening (the garbage went into a version comparison, not an authentication decision), but the fail-closed posture is correct per CLAUDE.md § Fail Secure. |
| T-44-04 | Tampering (T) | `parse_windows_registry_value` case-sensitive name match (WR-06 P43) | mitigate | Fixed: `eq_ignore_ascii_case` for value-name comparison; matches Windows registry semantics. The threat is masking platform detection — silently degrading to `CurrentVersion`'s "6.3" fallback on case-mismatched stored names; this opened a path-to-incorrect-policy-decision via wrong-platform routing. Regression test pins the fix. |
| T-44-05 | Denial of service (D) | `refresh_synchronous` startup latency hit (WR-05 P43) | mitigate | Fixed: synchronous path DELETED entirely per D-44-B2 option (b). A dead registry can no longer stall `nono run` startup up to 5 minutes per pack. First-run users see hints on 2nd run instead. CLAUDE.md § Performance "Zero startup latency" constraint preserved. |
| T-44-06 | Elevation of privilege (E) | hidden `--dangerous-force-wfp-ready` flag failing doc-check (WR-10 P37) | mitigate | The flag is `hide = true` for security reasons (intentionally undocumented). The doc-check parser fix (skip `hide = true` accumulated attrs) does NOT expose the flag to docs; it just stops the parser from exiting non-zero on intentionally-hidden flags. Defense-in-depth: hidden flags STAY hidden. |
| T-44-07 | Repudiation (R) | DCO sign-off requirement on every commit | mitigate | Every commit message in Plan 44-01 carries `Signed-off-by: <Name> <email>` per CLAUDE.md § Coding Standards + project convention. Pre-commit hook enforcement (if installed) catches missing trailers; otherwise the verifier's `git log --grep 'Signed-off-by'` count must equal the commit count for Plan 44-01. |
| T-44-08 | Information disclosure (I) | sigstore-verify 0.7.0 `verify_sct` default silently flipping (WR-05 P37) | mitigate | Pin-test `verification_policy_default_enables_sct_verification` asserts `VerificationPolicy::default().verify_sct == true`. Any future minor bump that flips this default forces an audit before the bump can merge. Preserves the trust posture documented in `crates/nono/Cargo.toml:48`. |
</threat_model>

<verification>
## Phase-level checks for REQ-REVIEW-FU-01

After all 9 tasks complete:

1. **No silent ignores** — every WR + IN in 37-REVIEW.md + 43-REVIEW.md has a row in the canonical disposition table above with a non-empty `Commit Ref`. Roadmap SC#1.
2. **Production reader wired** — `grep -rn 'NONO_TRUST_OIDC_ISSUER' crates/` returns at-least 2 matches (reader + consumer). 37-REVIEW.md WR-09 closed.
3. **Synchronous pack-update gone** — `grep -c 'fn refresh_synchronous' crates/nono-cli/src/pack_update_hint.rs` returns 0. 43-REVIEW.md WR-05 closed per D-44-B2.
4. **TOCTOU doc + todo** — `grep -c 'Residual race window' crates/nono/src/undo/snapshot.rs` returns at-least 1; the follow-up todo file exists.
5. **CGROUP_V2_HINT dedup** — `grep -v '^#' crates/nono-cli/src/exec_strategy/supervisor_linux.rs | grep -c 'cgroup v2 required'` returns 0.
6. **test_env.rs gate widened** — `grep -c 'cfg(any(target_os = "windows", target_os = "linux"))' crates/nono-cli/tests/common/test_env.rs` returns 1; `grep -c 'pub fn lock_env' crates/nono-cli/tests/common/test_env.rs` returns 1.
7. **Workflow no longer relies on --test-threads=1** — `grep -v '^#' .github/workflows/phase-37-linux-resl.yml | grep -c 'test-threads=1'` returns 0.
8. **Workspace builds + tests pass on Windows host** — `cargo build --workspace` exits 0; `cargo test --workspace` exits 0 modulo platform-gated tests.
9. **Cross-target clippy log present** — `44-01-CLIPPY-CROSS-TARGET.md` exists with one row per in-scope commit; verdicts are PASS or PARTIAL (no FAIL).
10. **DCO sign-off on every commit** — `git log --grep 'Signed-off-by' --oneline | wc -l` ≥ count of Plan 44-01 commits since the Phase 44 branch base.
</verification>

<success_criteria>
**Plan 44-01 is complete when:**

- [ ] All 28 rows in the Canonical Disposition Table have a non-TBD `Commit Ref` (every WR + IN closed)
- [ ] `crates/nono/src/trust/signing.rs` contains `pub fn configured_oidc_issuer()` with 3 passing unit tests
- [ ] `crates/nono-cli/src/pack_update_hint.rs` no longer defines `refresh_synchronous`
- [ ] `crates/nono/src/undo/snapshot.rs` doc comment above `validate_restore_target` contains the "Residual race window" paragraph
- [ ] `.planning/todos/pending/44-validate-restore-target-fd-relative-hardening.md` exists
- [ ] `crates/nono/src/error.rs` exports `pub const CGROUP_V2_HINT`; all 6 sites in `supervisor_linux.rs` reference it
- [ ] `crates/nono-cli/src/platform.rs` has the case-insensitive name match + None-on-malformed-DWORD fix + symmetric `compare_versions` + 3 new regression tests
- [ ] `crates/nono-cli/tests/common/test_env.rs` gate is `any(target_os = "windows", target_os = "linux")` and the file exports `pub fn lock_env`
- [ ] `crates/nono-cli/tests/auto_pull_e2e_linux.rs` uses canonical `lock_env() + EnvVarGuard`, pins XDG_CONFIG_HOME in all 5 tests, and has NO file-local `EnvGuard` struct
- [ ] `.github/workflows/phase-37-linux-resl.yml` does not contain `--test-threads=1`
- [ ] `.github/scripts/check-cli-doc-flags.sh` accumulates multi-line `#[arg(...)]` blocks and skips `hide = true` fields; the script exits 0 against the current source tree
- [ ] `crates/nono-cli/src/format_util.rs` exists; `format_bytes_short` is no longer duplicated in `session_commands.rs` / `session_commands_windows.rs`
- [ ] `.planning/phases/44-review-polish-test-hygiene-drain/44-01-CLIPPY-CROSS-TARGET.md` has one row per cfg-gated-Unix-touching commit with verdict PASS or PARTIAL (no FAIL)
- [ ] Every commit on the Phase 44 feature branch carries a `Signed-off-by:` trailer
- [ ] `cargo build --workspace` exits 0 on Windows host
- [ ] `cargo test --workspace` exits 0 modulo platform-gated tests (Linux-gated tests skipped on Windows)
- [ ] Cross-target clippy on Linux + macOS exits 0 from the dev host (or REQ marked PARTIAL with explicit live-CI deferral per cross-target-verify-checklist)
</success_criteria>

<output>
After completion, create `.planning/phases/44-review-polish-test-hygiene-drain/44-01-SUMMARY.md` echoing the populated disposition table (with `Commit Ref` column filled), the cross-target clippy verification log result, and the list of new files created (the follow-up todo + format_util.rs + the clippy log).
</output>
