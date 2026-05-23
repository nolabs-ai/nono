---
phase: quick-260523-kzd
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - tools/sign-fixture/Cargo.toml
  - tools/sign-fixture/src/main.rs
  - Cargo.toml
  - .github/workflows/phase-37-linux-resl.yml
  - crates/nono-cli/src/exec_strategy/supervisor_linux.rs
autonomous: true
requirements: [REQ-CI-FU-01]
---

<objective>
Fix two independent compile-time bugs that prevent both jobs in `.github/workflows/phase-37-linux-resl.yml`
from reaching their integration tests.

BUG-1 (PKGS-04 job): `cargo build --release -p sigstore-sign --example sign_blob` fails because
`tokio` and `chrono` are only dev-dependencies of `sigstore-sign 0.7.0`. Cargo never fetches
dev-deps of external registry crates from a consumer workspace, so E0432/E0433/E0752 fire.
Fix: create a new `tools/sign-fixture/` workspace member that owns `tokio`+`chrono`+`sigstore-sign`
as regular `[dependencies]` and ports the `sign_blob` example logic into its `main.rs`.

BUG-2 (RESL-NIX job): Three test fn signatures in `supervisor_linux.rs` declare
`-> Result<(), Box<dyn std::error::Error>>`. The module-level `use nono::Result` (line 859) shadows
`std::result::Result`. `nono::Result<T>` is a single-arg alias; the two-arg form is only valid for
`std::result::Result`. Compiler emits E0107 + E0277 for each function.
Fix: change all three fn signatures to `-> std::result::Result<(), Box<dyn std::error::Error>>`.

Purpose: Unblock Plan 46-02 REQ-CI-FU-01, which requires a green live run of `phase-37-linux-resl.yml`
on ubuntu-24.04.

Output:
- `tools/sign-fixture/Cargo.toml` (new crate)
- `tools/sign-fixture/src/main.rs` (ported sign_blob logic)
- `Cargo.toml` (workspace members updated)
- `.github/workflows/phase-37-linux-resl.yml` (PKGS-04 job updated to use sign-fixture binary)
- `crates/nono-cli/src/exec_strategy/supervisor_linux.rs` (3 test fn signatures corrected)
- `.planning/quick/260523-kzd-fix-phase-37-resl-workflow-compile-bugs-/260523-kzd-SUMMARY.md`
</objective>

<execution_context>
@/c/Users/OMack/.claude/get-shit-done/workflows/execute-plan.md
@/c/Users/OMack/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/STATE.md
@.planning/ROADMAP.md

<interfaces>
<!-- Key types extracted from the sign_blob.rs example (sigstore-sign 0.7.0). -->
<!-- Executor must port this logic verbatim into tools/sign-fixture/src/main.rs. -->

From ~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/sigstore-sign-0.7.0/examples/sign_blob.rs:
```rust
use sigstore_oidc::{get_identity_token, IdentityToken};
use sigstore_rekor::RekorApiVersion;
use sigstore_sign::{SigningConfig, SigningContext};
```
CLI args accepted: `<ARTIFACT>` (positional), `-o`/`--output`, `-t`/`--token`, `--staging`, `--v2`, `-h`/`--help`.
The workflow calls: `cargo run --release -p sign-fixture -- artifact.tar.gz -o artifact.tar.gz.sigstore.json`
so the binary must accept exactly this interface.

From the RESL-NIX failure root cause (phase-37-resl-failure.md):
```
// Line 859 — in cgroup module, NOT in tests:
use nono::{NonoError, Result, CGROUP_V2_HINT};

// Lines 1451, 1474, 1505 — BROKEN (two-arg form invalid for nono::Result):
fn cgroup_session_apply_limits() -> Result<(), Box<dyn std::error::Error>> {
fn cgroup_session_pre_exec_places_pid() -> Result<(), Box<dyn std::error::Error>> {
fn cgroup_kill_terminates_grandchildren() -> Result<(), Box<dyn std::error::Error>> {

// Fix (std-qualified form):
fn cgroup_session_apply_limits() -> std::result::Result<(), Box<dyn std::error::Error>> {
fn cgroup_session_pre_exec_places_pid() -> std::result::Result<(), Box<dyn std::error::Error>> {
fn cgroup_kill_terminates_grandchildren() -> std::result::Result<(), Box<dyn std::error::Error>> {
```

From sigstore-sign 0.7.0 Cargo.toml (registry):
- Regular deps: `sigstore-oidc 0.7.0`, `sigstore-rekor 0.7.0`, `sigstore-sign 0.7.0`, `sigstore-bundle 0.7.0`
- Dev-deps (missing from consumer workspace): `tokio 1.47 (full)`, `chrono 0.4 (serde)`
- The sign-fixture crate must declare tokio + chrono as regular `[dependencies]`
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: BUG-1 fix — create tools/sign-fixture workspace member crate</name>
  <files>tools/sign-fixture/Cargo.toml, tools/sign-fixture/src/main.rs, Cargo.toml</files>
  <read_first>
    - `Cargo.toml` (workspace root) — already confirmed members list and workspace.dependencies
    - `/c/Users/OMack/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/sigstore-sign-0.7.0/examples/sign_blob.rs` — source logic to port
    - `tools/` directory listing — confirmed it exists (contains `docker/` and `test-update-server.py`); place crate at `tools/sign-fixture/`
  </read_first>
  <action>
1. Create `tools/sign-fixture/Cargo.toml`:
   ```toml
   [package]
   name = "sign-fixture"
   version = "0.1.0"
   edition = "2021"
   rust-version = "1.77"
   description = "CI fixture signing tool — replaces sigstore-sign --example sign_blob (dev-dep workaround)"
   publish = false

   [[bin]]
   name = "sign-fixture"
   path = "src/main.rs"

   [dependencies]
   sigstore-sign = "0.7.0"
   sigstore-oidc = "0.7.0"
   sigstore-rekor = "0.7.0"
   tokio = { version = "1", features = ["full"] }
   chrono = { version = "0.4", features = ["serde"] }
   ```
   Note: `sigstore-oidc` and `sigstore-rekor` must be declared explicitly because the example code
   directly imports `sigstore_oidc::get_identity_token` and `sigstore_rekor::RekorApiVersion`.
   These are transitive deps of `sigstore-sign` but must be direct here to import them explicitly.

2. Create `tools/sign-fixture/src/main.rs` by porting the sign_blob example verbatim.
   The example already uses `process::exit` for error paths (no panics, no `.unwrap()`).
   The `chrono` import appears only in the `integrated_time` display block inside main (line 203
   of the original: `use chrono::{DateTime, Utc};` — keep this as an inner use statement, unchanged).
   Do NOT add any `.unwrap()` or `.expect()` calls that aren't in the original source.
   Keep all `process::exit(1)` error paths as-is (acceptable in a tools binary; this is not
   part of the security-critical library surface per CLAUDE.md).

3. Update root `Cargo.toml` `members` list — add `"tools/sign-fixture"` as a new entry:
   ```toml
   members = [
       "crates/nono",
       "crates/nono-cli",
       "crates/nono-proxy",
       "crates/nono-shell-broker",
       "bindings/c",
       "tools/sign-fixture",
   ]
   ```

4. Commit with DCO sign-off:
   ```
   feat(quick-260523-kzd): add tools/sign-fixture workspace member (BUG-1)

   Port sigstore-sign sign_blob example into a dedicated workspace crate that
   declares tokio and chrono as regular [dependencies]. This bypasses the
   dev-dependency availability limitation when building upstream examples from
   a consumer workspace (Cargo does not fetch external crates' dev-deps).

   Signed-off-by: Oscar Mack Jr <oscar.mack.jr@gmail.com>
   ```
  </action>
  <verify>
    <automated>cargo check -p sign-fixture 2>&amp;1 | tail -5</automated>
    Expect: no errors. If `sigstore-oidc` or `sigstore-rekor` version resolution fails, check
    `Cargo.lock` for the version already pinned by sigstore-sign's transitive graph and use that exact version.
  </verify>
  <acceptance_criteria>
    - `tools/sign-fixture/Cargo.toml` exists with `sigstore-sign`, `tokio`, `chrono` in `[dependencies]`
    - `tools/sign-fixture/src/main.rs` compiles via `cargo check -p sign-fixture`
    - Root `Cargo.toml` `members` list includes `"tools/sign-fixture"`
    - `cargo check --workspace` passes (Windows host)
    - Commit message follows `feat(quick-260523-kzd):` convention with DCO sign-off
  </acceptance_criteria>
</task>

<task type="auto">
  <name>Task 2: BUG-1 wiring — update phase-37-linux-resl.yml PKGS-04 job</name>
  <files>.github/workflows/phase-37-linux-resl.yml</files>
  <read_first>
    - `.github/workflows/phase-37-linux-resl.yml` — already read; the two steps to edit are:
      - Step "Build workspace and sigstore-sign example" (line 186): contains `cargo build --release -p sigstore-sign --example sign_blob` at line 192
      - Step "Sign fixture artifact with sigstore-sign (keyless via GH Actions OIDC)" (line 273): contains `cargo run --release -p sigstore-sign --example sign_blob -- ...` at line 278
  </read_first>
  <action>
1. In the step named "Build workspace and sigstore-sign example" (around line 186–192):
   Replace the second `cargo build` line:
   ```yaml
   # BEFORE:
   cargo build --release -p sigstore-sign --example sign_blob
   # AFTER:
   cargo build --release -p sign-fixture
   ```
   Update the comment above that line to reflect the new crate:
   ```yaml
   # Compile the workspace fixture signing tool used to mint the
   # ephemeral Sigstore bundle for the auto-pull e2e fixture (D-13).
   # tools/sign-fixture ports the sign_blob example logic with tokio
   # and chrono as regular deps (avoids dev-dep availability limitation).
   cargo build --release -p sign-fixture
   ```

2. In the step named "Sign fixture artifact with sigstore-sign (keyless via GH Actions OIDC)"
   (around line 273–281):
   Replace the `cargo run` invocation:
   ```yaml
   # BEFORE:
   cargo run --release -p sigstore-sign --example sign_blob -- \
     artifact.tar.gz \
     -o artifact.tar.gz.sigstore.json
   # AFTER:
   cargo run --release -p sign-fixture -- \
     artifact.tar.gz \
     -o artifact.tar.gz.sigstore.json
   ```
   All other arguments (`artifact.tar.gz`, `-o artifact.tar.gz.sigstore.json`) are preserved unchanged.
   The `SIGSTORE_ID_TOKEN_AUDIENCE: sigstore` env var and step name remain unchanged.

3. Commit with DCO sign-off:
   ```
   fix(quick-260523-kzd): update PKGS-04 job to use sign-fixture binary (BUG-1)

   Replace the broken `cargo build/run -p sigstore-sign --example sign_blob`
   invocations with the new sign-fixture workspace member. Preserves all
   signing semantics and OIDC token flow (D-13).

   Signed-off-by: Oscar Mack Jr <oscar.mack.jr@gmail.com>
   ```
  </action>
  <verify>
    <automated>grep -n "sign-fixture\|sign_blob" .github/workflows/phase-37-linux-resl.yml</automated>
    Expect: `sign-fixture` appears in both the build step and the run step; `sign_blob` does NOT appear.
  </verify>
  <acceptance_criteria>
    - `grep -c "sign_blob" .github/workflows/phase-37-linux-resl.yml` returns `0` (the broken invocation is gone)
    - `grep -c "sign-fixture" .github/workflows/phase-37-linux-resl.yml` returns `2` (build step + run step)
    - The signing step's argument list (`artifact.tar.gz -o artifact.tar.gz.sigstore.json`) is identical to before
    - The `SIGSTORE_ID_TOKEN_AUDIENCE: sigstore` env var remains on the signing step
    - Commit message follows `fix(quick-260523-kzd):` convention with DCO sign-off
  </acceptance_criteria>
</task>

<task type="auto">
  <name>Task 3: BUG-2 fix + workspace verification + SUMMARY</name>
  <files>
    crates/nono-cli/src/exec_strategy/supervisor_linux.rs,
    .planning/quick/260523-kzd-fix-phase-37-resl-workflow-compile-bugs-/260523-kzd-SUMMARY.md
  </files>
  <read_first>
    - `crates/nono-cli/src/exec_strategy/supervisor_linux.rs` lines 1448–1515 — confirmed live line
      numbers match debug report (1451, 1474, 1505); verify before editing
  </read_first>
  <action>
1. Verify current line numbers by grepping before editing:
   ```bash
   grep -n "-> Result<(), Box<dyn std::error::Error>>" \
     crates/nono-cli/src/exec_strategy/supervisor_linux.rs
   ```
   Confirm output shows exactly 3 matches. If line numbers have shifted, use the grep output as the
   authoritative locations.

2. Edit the three test fn signatures — change ONLY the return type annotation:
   - Line ~1451: `fn cgroup_session_apply_limits() -> Result<(), Box<dyn std::error::Error>> {`
     → `fn cgroup_session_apply_limits() -> std::result::Result<(), Box<dyn std::error::Error>> {`
   - Line ~1474: `fn cgroup_session_pre_exec_places_pid() -> Result<(), Box<dyn std::error::Error>> {`
     → `fn cgroup_session_pre_exec_places_pid() -> std::result::Result<(), Box<dyn std::error::Error>> {`
   - Line ~1505: `fn cgroup_kill_terminates_grandchildren() -> Result<(), Box<dyn std::error::Error>> {`
     → `fn cgroup_kill_terminates_grandchildren() -> std::result::Result<(), Box<dyn std::error::Error>> {`

   Do NOT touch line 859 (`use nono::{NonoError, Result, CGROUP_V2_HINT}`). The non-test module
   code uses `nono::Result` correctly (single-arg form). Only the three test fn signatures are broken.

3. Run workspace-local verification (Windows host):
   ```bash
   cargo check --workspace
   cargo fmt --all -- --check
   cargo test -p nono-cli --bin nono \
     exec_strategy::supervisor_linux::cgroup::cgroup_session_apply_limits \
     exec_strategy::supervisor_linux::cgroup::cgroup_session_pre_exec_places_pid \
     exec_strategy::supervisor_linux::cgroup::cgroup_kill_terminates_grandchildren \
     2>&1 | tail -20
   ```
   Note: The three tests themselves require cgroup v2 (Linux-only runtime). On Windows they will
   report `test ... -- IGNORED` or compile-only. The goal of running them on Windows is to confirm
   the fn signatures compile cleanly — not to execute the tests.

   If `cargo check --workspace` passes: cross-target clippy is PARTIAL (see SUMMARY step).

4. Write `.planning/quick/260523-kzd-fix-phase-37-resl-workflow-compile-bugs-/260523-kzd-SUMMARY.md`
   using the summary template. Key sections:

   **bugs_fixed:**
   - BUG-1: Created `tools/sign-fixture/` workspace member with tokio+chrono as regular deps.
     Ported sign_blob example logic. Updated PKGS-04 job to use `cargo run -p sign-fixture`.
   - BUG-2: Changed 3 test fn signatures from `Result<(), Box<dyn std::error::Error>>` to
     `std::result::Result<(), Box<dyn std::error::Error>>` in supervisor_linux.rs (lines ~1451, 1474, 1505).
     Did not touch the `use nono::Result` import at line 859.

   **cross_target_clippy_status: PARTIAL**
   Rationale: Per CLAUDE.md § Coding Standards "Cross-target clippy verification" bullet +
   `.planning/templates/cross-target-verify-checklist.md`: the affected file
   `crates/nono-cli/src/exec_strategy/supervisor_linux.rs` contains `#[cfg(target_os = "linux")]`
   blocks. Windows-host `cargo check` does NOT exercise cfg-gated Linux branches.
   Cross-target clippy MUST run on Linux toolchain. The x86_64-unknown-linux-gnu cross-toolchain
   is not installed on this dev host.
   Deferred to: live `gh workflow run phase-37-linux-resl.yml` after push.

   **next_steps_for_operator:**
   1. `git push origin main`
   2. `gh workflow run phase-37-linux-resl.yml` (or wait for push-triggered run)
   3. Monitor via `gh run watch <run-id>`
   4. Confirm both jobs (`resl-nix` and `pkgs-auto-pull`) report `conclusion=success`
   5. On green: mark REQ-CI-FU-01 as satisfied in Plan 46-02 VERIFICATION.md

5. Commit BUG-2 fix + SUMMARY together with DCO sign-off:
   ```
   fix(quick-260523-kzd): std-qualify Result in 3 test fn signatures (BUG-2)

   The cgroup module's `use nono::Result` (line 859) shadows std::result::Result.
   nono::Result<T> is a single-arg alias; three test fn signatures used the
   two-arg form, causing E0107 + E0277 on Linux clippy gate. Fully-qualify
   std::result::Result in the three affected test fns only.

   Cross-target Linux clippy: PARTIAL — deferred to live workflow re-dispatch
   per CLAUDE.md cross-target verification rule.

   Signed-off-by: Oscar Mack Jr <oscar.mack.jr@gmail.com>
   ```
  </action>
  <verify>
    <automated>
      cargo check --workspace 2>&amp;1 | tail -5
      grep -c "-> Result&lt;(), Box&lt;dyn std::error::Error&gt;&gt;" crates/nono-cli/src/exec_strategy/supervisor_linux.rs
    </automated>
    Expect: `cargo check --workspace` exits 0; grep count returns `0` (no unqualified two-arg form remains).
    Also verify: `grep -c "-> std::result::Result" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` returns `3`.
  </verify>
  <acceptance_criteria>
    - `cargo check --workspace` passes on Windows host
    - Zero occurrences of `-> Result<(), Box<dyn std::error::Error>>` in supervisor_linux.rs
    - Three occurrences of `-> std::result::Result<(), Box<dyn std::error::Error>>` in supervisor_linux.rs
    - Line 859 `use nono::{NonoError, Result, CGROUP_V2_HINT}` is unchanged
    - `260523-kzd-SUMMARY.md` exists with `cross_target_clippy_status: PARTIAL` and next-steps
    - Commit message follows `fix(quick-260523-kzd):` convention with DCO sign-off
  </acceptance_criteria>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| CI runner → sign-fixture binary | Artifact bytes + OIDC token flow through the new binary; same trust surface as the original sign_blob example |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-kzd-01 | Spoofing | sign-fixture OIDC token flow | accept | Token acquisition logic is a direct port of the upstream sign_blob example; no new attack surface introduced. OIDC issuer pinning remains in the test via `NONO_TRUST_OIDC_ISSUER` env var. |
| T-kzd-02 | Tampering | tools/sign-fixture as workspace member | accept | `publish = false` prevents accidental crates.io publication. The binary is CI-only tooling, not part of the sandboxing primitive surface. |
</threat_model>

<verification>
Run after all three tasks are committed:

```bash
# Workspace compiles cleanly
cargo check --workspace

# Format is clean
cargo fmt --all -- --check

# BUG-2: no unqualified two-arg Result in test fns
grep -c "-> Result<(), Box<dyn std::error::Error>>" \
  crates/nono-cli/src/exec_strategy/supervisor_linux.rs
# Expected: 0

# BUG-2: three std-qualified signatures present
grep -c "-> std::result::Result<(), Box<dyn std::error::Error>>" \
  crates/nono-cli/src/exec_strategy/supervisor_linux.rs
# Expected: 3

# BUG-1: sign_blob reference is gone from workflow
grep -c "sign_blob" .github/workflows/phase-37-linux-resl.yml
# Expected: 0

# BUG-1: sign-fixture used in both build and run steps
grep -c "sign-fixture" .github/workflows/phase-37-linux-resl.yml
# Expected: 2

# New crate is registered
grep "tools/sign-fixture" Cargo.toml
# Expected: 1 match
```

**Cross-target clippy: PARTIAL — deferred to live CI.**
Per CLAUDE.md and `.planning/templates/cross-target-verify-checklist.md`, Linux cfg-gated code
in `supervisor_linux.rs` requires `cargo clippy --workspace --target x86_64-unknown-linux-gnu`.
This cannot run on the Windows dev host. Operator must push and re-dispatch
`phase-37-linux-resl.yml` to complete verification.
</verification>

<success_criteria>
1. `cargo check --workspace` passes on Windows host (both bugs compile-clean locally)
2. `cargo fmt --all -- --check` passes
3. `grep -c "sign_blob" .github/workflows/phase-37-linux-resl.yml` = 0
4. `grep -c "sign-fixture" .github/workflows/phase-37-linux-resl.yml` = 2
5. `grep -c "-> Result<(), Box<dyn std::error::Error>>" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` = 0
6. Three atomic commits with `fix(quick-260523-kzd):` / `feat(quick-260523-kzd):` prefix + DCO sign-off
7. `260523-kzd-SUMMARY.md` exists documenting PARTIAL cross-target status and next steps
8. After operator pushes: live workflow run reports both jobs `conclusion=success` (unblocks REQ-CI-FU-01)
</success_criteria>

<output>
After completing all three tasks, create:
`.planning/quick/260523-kzd-fix-phase-37-resl-workflow-compile-bugs-/260523-kzd-SUMMARY.md`

The SUMMARY must include:
- `bugs_fixed`: BUG-1 (tools/sign-fixture) + BUG-2 (supervisor_linux.rs 3 test fns)
- `cross_target_clippy_status: PARTIAL` with rationale
- `next_steps`: push → re-dispatch workflow → verify both jobs green → mark REQ-CI-FU-01 satisfied
- `commits`: list of the 3 commit hashes with their subjects
</output>
