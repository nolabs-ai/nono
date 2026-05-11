---
phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
plan_number: 34-07
plan: 07
slug: ps-envuri
cluster_id: C10
type: execute
wave: 2
depends_on: ["34-04", "34-01", "34-02", "34-05"]
blocks: []
files_modified:
  - crates/nono-cli/src/cli.rs
  - crates/nono-cli/src/session_commands.rs
  - crates/nono-cli/src/profile/mod.rs
  - crates/nono/src/keystore.rs
upstream_tag_range: v0.50.0..v0.50.1
upstream_commit_count: 7
autonomous: true
requirements: [C10]
tags: [upst3, c10, ps, env-uri, ioctl, wave-2]

must_haves:
  truths:
    - "All 7 cluster-C10 commits cherry-picked onto `main` in upstream chronological order"
    - "Every Plan 34-07 commit body carries the verbatim D-19 6-line trailer block"
    - "`env://` URI scheme in custom_credentials credential_key (`ca2e948e`) composes with fork's existing keystore `env://` (Phase 20 UPST-03)"
    - "`nono ps` column display improved (`a9eeb3fa`, `7547f91f`) — fork's Windows session-listing surface gets visual parity"
    - "Linux ioctl native types fix (`4e642f29`) lands as Linux-only (fork's POC Linux side inherits)"
    - "D-34-E1 invariant: zero edits to `*_windows.rs` for every commit"
    - "All 8 D-34-D2 close-gates pass"
  artifacts:
    - path: "crates/nono/src/keystore.rs"
      provides: "`env://` URI scheme extension (composes with existing Phase 20 keystore `env://` support)"
      grep_pattern: "env://"
    - path: "crates/nono-cli/src/session_commands.rs"
      provides: "`nono ps` dynamic-column display (`a9eeb3fa`, `7547f91f`)"
      grep_pattern: "ps_command|dynamic_column"
    - path: "crates/nono-cli/src/profile/mod.rs"
      provides: "`custom_credentials.credential_key` accepts `env://` URI (`ca2e948e`)"
      grep_pattern: "credential_key.*env|env.*credential"
---

<objective>
Cluster C10 (upstream v0.50.0..v0.50.1, 7 commits): `env://` URI support in `custom_credentials.credential_key`, `nono ps` column display improvements, and a Linux ioctl native-types fix. The `env://` extension composes cleanly with fork's existing keystore `env://` support (Phase 20 UPST-03); the ps display fixes give fork's Windows session-listing surface visual parity with upstream.

Output: 7 atomic commits with D-19 trailers.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@CLAUDE.md
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md
@.planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md
@.planning/templates/upstream-sync-quick.md
@crates/nono/src/keystore.rs
@crates/nono-cli/src/session_commands.rs

<interfaces>
**Cluster C10 cherry-pick chain (7 commits, chronological):**

| Order | SHA | Tag | Subject | Upstream Author |
|-------|-----|-----|---------|-----------------|
| 1 | `0b29d8ba` | v0.50.0 | restore comment | SequeI <asiek@redhat.com> |
| 2 | `7547f91f` | v0.50.0 | refactor(cli): optimize ps command column width calculation | Luke Hinds <lukehinds@gmail.com> |
| 3 | `a9eeb3fa` | v0.50.0 | refactor(cli/ps): improve ps command display with dynamic columns | Luke Hinds <lukehinds@gmail.com> |
| 4 | `ca2e948e` | v0.50.0 | feat(profile): support env:// URI in custom_credentials credential_key | SequeI <asiek@redhat.com> |
| 5 | `cd74c4cf` | v0.50.0 | chore: release v0.50.0 | Luke Hinds <lukehinds@gmail.com> |
| 6 | `2d183e8f` | v0.50.1 | chore: release v0.50.1 | Luke Hinds <lukehinds@gmail.com> |
| 7 | `4e642f29` | v0.50.1 | fix: Use native types for iotcl integers | Tyler Gilbert <tyler.w.gilbert@gmail.com> |

**Plan ordering note:** Wave 2 plans (34-02, 34-05, 34-07, 34-08) all touch `cli.rs`. Plan 34-07's commits should land AFTER Plans 34-02 (C4 v0.42-v0.45) and 34-05 (C8 v0.48) per upstream chronological order.

**Fork-divergence catalog:**

- **Fork's `keystore.rs::load_secret` already supports `env://` URIs** (Phase 20 UPST-03; see CLAUDE.md § Configuration "Supports `env://` URI scheme for credentials"). After cherry-picking `ca2e948e`, verify the profile-side extension routes through the EXISTING keystore loader:
  ```bash
  grep -c 'env://' crates/nono/src/keystore.rs   # Expected: ≥ 1 (existing)
  grep -c 'load_secret.*credential_key\|credential_key.*load_secret' crates/nono-cli/src/profile/mod.rs   # Expected: ≥ 1 (new wiring)
  ```

- **Fork's `nono ps` Windows session-listing** (Phase 02-04 era) — the display refactors (`7547f91f`, `a9eeb3fa`) touch cross-platform code; Windows session-data structure is fork-internal but the display rendering is cross-platform. Verify after commits 2-3:
  ```bash
  cargo run --quiet --bin nono -- ps 2>&1 | head -5
  # Expected: column-aligned output (verify visual parity)
  ```

- **Linux ioctl fix (`4e642f29`)** lands in `crates/nono-cli/src/exec_strategy/linux.rs` (fork's Linux POC path). NO Windows analog — Windows backend uses different syscalls. Verify after commit 7:
  ```bash
  git diff --stat HEAD~1 HEAD -- crates/nono-cli/src/exec_strategy_windows/ | wc -l   # Expected: 0
  ```
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Pre-flight — verify Plans 34-04, 34-01, 34-02, 34-05 closed</name>
  <files>(git operations only)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-A2
    - crates/nono/src/keystore.rs § existing env:// support (Phase 20 UPST-03)
  </read_first>
  <action>
    1. Verify Plans 34-04 + 34-01 + 34-02 + 34-05 closed.
    2. `git fetch upstream --tags`.
    3. Verify all 7 C10 SHAs reachable.
    4. Capture pre-Plan-34-07 HEAD + verify keystore `env://` is functional:
       ```
       grep -c 'env://' crates/nono/src/keystore.rs   # Expected: ≥ 1 baseline (Phase 20 UPST-03)
       ```
    5. `cargo build --workspace`.
  </action>
  <verify>
    <automated>git fetch upstream --tags &amp;&amp; cargo build --workspace &amp;&amp; grep -c 'env://' crates/nono/src/keystore.rs</automated>
  </verify>
  <acceptance_criteria>
    - All dependent plans closed; 7 SHAs reachable; baseline `env://` count recorded.
  </acceptance_criteria>
  <done>
    Ready for C10 chain.
  </done>
</task>

<task type="auto">
  <name>Task 2: Cherry-pick all 7 C10 commits with D-19 trailers</name>
  <files>
    crates/nono-cli/src/cli.rs
    crates/nono-cli/src/session_commands.rs
    crates/nono-cli/src/profile/mod.rs
    crates/nono/src/keystore.rs
  </files>
  <read_first>
    - crates/nono-cli/src/session_commands.rs § current `ps` command implementation
    - crates/nono-cli/src/profile/mod.rs § `custom_credentials.credential_key` field
    - crates/nono/src/keystore.rs § `load_secret` existing `env://` handling
    - `git show 0b29d8ba 7547f91f a9eeb3fa ca2e948e cd74c4cf 2d183e8f 4e642f29 --stat`
  </read_first>
  <action>
    For each of the 7 commits, follow the per-commit pattern.

    **Critical attention for commit 4 (`ca2e948e` env:// URI):**

    After cherry-pick, verify the new wiring routes through fork's EXISTING keystore loader (NOT a duplicate `env://` parser):
    ```bash
    # Verify single canonical env:// resolution path:
    grep -n 'env://' crates/nono-cli/src/profile/mod.rs crates/nono/src/keystore.rs
    # The profile/mod.rs side should DELEGATE to keystore.rs::load_secret, not parse env:// itself.
    # If upstream's commit duplicates the parsing, fold the duplication into the existing keystore loader (single source of truth).
    cargo test -p nono keystore::tests::env_uri   # Verify env:// regression tests pass
    ```

    **Per-commit template:**

    ```bash
    git cherry-pick <sha>
    cargo build --workspace
    git commit --amend -m "$(cat <<'EOF'
    <upstream subject verbatim>

    Upstream-commit: <8-char sha>
    Upstream-tag: <v0.50.0 | v0.50.1>
    Upstream-author: <name> <<email>>
    Co-Authored-By: <name> <<email>>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    After all 7:
    ```bash
    git log --format='%B' HEAD~7..HEAD | grep -c '^Upstream-commit: '   # Expected: 7
    git log --format='%B' HEAD~7..HEAD | grep -c '^Signed-off-by: '     # Expected: 14

    # Smoke tests:
    cargo run --quiet --bin nono -- ps 2>&1 | head -5   # Dynamic-column ps output
    # env:// credential resolution test would need a profile fixture — covered by cargo test
    ```
  </action>
  <verify>
    <automated>git log --format='%B' HEAD~7..HEAD | grep -c '^Upstream-commit: ' | grep -E '^7$' &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - 7 commits with D-19 trailers (lowercase 'a').
    - Per-commit D-34-E1 invariant returned 0.
    - `env://` URI scheme functional in `custom_credentials.credential_key` (delegates to keystore, no duplicate parser).
    - `nono ps` produces dynamic-column output.
    - Linux ioctl fix lands in Linux-only path (no Windows touch).
  </acceptance_criteria>
  <done>
    C10 chain complete.
  </done>
</task>

<task type="auto">
  <name>Task 3: D-34-D2 close-gate</name>
  <files>(read-only verification)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-D2
  </read_first>
  <action>
    Run all 8 close-gates.
  </action>
  <verify>
    <automated>cargo test --workspace --all-features &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo fmt --all -- --check</automated>
  </verify>
  <acceptance_criteria>
    - All 8 close-gates pass.
  </acceptance_criteria>
  <done>
    Plan 34-07 close-gate cleared.
  </done>
</task>

<task type="auto">
  <name>Task 4: Push + PR</name>
  <files>(git push only)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-D1
  </read_first>
  <action>
    1. `git push origin main`.
    2. `gh pr create --title "Plan 34-07 (C10): nono ps + env:// URI + ioctl (v0.50.0–v0.50.1, 7 commits)"`.
  </action>
  <verify>
    <automated>git fetch origin &amp;&amp; test "$(git log origin/main..main --oneline | wc -l)" = "0"</automated>
  </verify>
  <acceptance_criteria>
    - Pushed; PR opened.
  </acceptance_criteria>
  <done>
    Plan 34-07 published.
  </done>
</task>

</tasks>

<non_goals>
**No `*_windows.rs` touched.** `4e642f29` Linux ioctl fix is Linux-only.

**No duplicate `env://` parser.** Fork's `keystore.rs::load_secret` is the canonical resolver; profile-side `custom_credentials.credential_key` DELEGATES, doesn't reparse.

**No Windows session-listing data-structure changes.** `nono ps` display refactors are display-side only; fork's session-data backbone is unchanged.

**No Linux ioctl retrofit into Windows.** The native-types fix is Linux-specific (different syscall surface on Windows).
</non_goals>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Process env-var → credential resolution | `env://CREDENTIAL_NAME` reads from the current process environment. Trust boundary: parent process supplies env-vars. |
| Session-data tree → ps display rendering | Display-side refactors must not leak session-internal data outside its existing surface. |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation |
|-----------|----------|-----------|----------|-------------|------------|
| T-34-07-01 | Tampering | D-21 Windows-only files invariant violation | **high** | mitigate (BLOCKING) | Per-commit D-34-E1 invariant. |
| T-34-07-02 | Repudiation | D-19 trailer missing | **high** | mitigate (BLOCKING) | Task 2 smoke. |
| T-34-07-03 | Information Disclosure | `env://` extension introduces duplicate parser that handles untrusted env-var values differently than `keystore.rs` (inconsistent fail-closed semantics) | medium | mitigate | Task 2 verifies profile/mod.rs delegates to keystore.rs::load_secret. If upstream introduces duplication, fold into the existing canonical path. |
| T-34-07-04 | Tampering | `nono ps` dynamic column rendering crashes on session names with terminal-control chars | low | mitigate | Plan 34-03's char-aware truncation + Plan 34-05's string-truncation utility apply. Tests cover boundary cases. |
| T-34-07-05 | Information Disclosure | `nono ps` exposes session-internal state (e.g., environment variables) in display columns | low | accept | Existing fork `ps` display surface already filters secrets; new dynamic-column logic operates on the same filtered data. |
</threat_model>

<verification>
- All 8 D-34-D2 close-gates pass.
- `git log --format='%B' HEAD~7..HEAD | grep -c '^Upstream-commit: '` returns `7`.
- Per-commit D-34-E1 invariant: 0 hits.
- `nono ps` produces dynamic-column output.
- `env://` URI in `custom_credentials.credential_key` delegates to keystore (no duplicate parser).
</verification>

<success_criteria>
- 7 atomic commits on `main`, each with D-19 trailer.
- `env://` URI scheme functional in custom_credentials (delegates to existing keystore loader).
- `nono ps` dynamic-column display landed.
- Linux ioctl native-types fix landed (Linux-only).
- All 8 D-34-D2 gates green.
- `origin/main` advanced; PR opened.
</success_criteria>

<output>
After completion, create `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-07-SUMMARY.md`.
</output>
