---
phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
plan_number: 34-03
plan: 03
slug: keyring
cluster_id: C5
type: execute
wave: 1
depends_on: ["34-04"]
blocks: []
files_modified:
  - crates/nono/Cargo.toml
  - crates/nono/src/keystore.rs
  - crates/nono-cli/src/audit_display.rs
  - crates/nono-cli/src/audit_show.rs
  - Cargo.lock
upstream_tag_range: v0.43.0..v0.45.0
upstream_commit_count: 8
autonomous: true
requirements: [C5]
tags: [upst3, c5, keyring, display, audit, wave-1]

must_haves:
  truths:
    - "All 8 cluster-C5 commits cherry-picked onto `main` in upstream chronological order"
    - "Every Plan 34-03 commit body carries the verbatim D-19 6-line trailer block"
    - "`system-keyring` is the default feature for backward compatibility (`7b58c3ee`); optional for headless builds (`f5215917`)"
    - "Audit-display char-aware truncation (`91476107`) + shell-quote command args (`e21e27d1`) landed — fork's Windows audit-show surface (Phase 23 REQ-AUD-05) consumes byte-identically"
    - "Smoke check: `git log --format='%B' HEAD~8..HEAD | grep -c '^Upstream-commit: '` equals 8"
    - "D-34-E1 invariant: zero edits to `*_windows.rs` for every commit"
    - "Fork's Windows Credential Manager (`keyring v3 windows-native`) path remains functional after feature-flag change (verify Phase 21 fork-side cred-mgr test)"
    - "All 8 D-34-D2 close-gates pass"
  artifacts:
    - path: "crates/nono/Cargo.toml"
      provides: "`system-keyring` feature (default) with optional opt-out for headless builds"
      grep_pattern: "system-keyring|system_keyring"
    - path: "crates/nono-cli/src/audit_display.rs"
      provides: "Char-aware truncation in truncate_command (`91476107`); shell-quote command args in display output (`e21e27d1`)"
      grep_pattern: "truncate_command|shell_quote|char_aware"
  key_links:
    - from: "User running headless `nono` build (e.g., CI, MSI service install)"
      to: "Opt-out of `system-keyring` feature"
      via: "Cargo.toml feature flag composition; `cargo build --no-default-features` path"
      pattern: "default-features"
    - from: "Fork's Phase 23 audit-show surface"
      to: "Upstream's display-side fixes (`91476107`, `e21e27d1`)"
      via: "byte-identical consumption (audit-display crate is cross-platform)"
      pattern: "audit_display|truncate_command|shell_quote"
---

<objective>
Cluster C5 (upstream v0.43.0..v0.45.0, 8 commits): make `system-keyring` an optional feature for headless builds + audit-display char-aware truncation + shell-quote command args. The display fixes (`91476107`, `e21e27d1`) close real display bugs in fork's Phase 23 audit-show surface.

Output: 8 atomic commits with D-19 trailers. Headless-build support landed; audit-display rendering corrected.
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
@crates/nono/Cargo.toml

<interfaces>
**Cluster C5 cherry-pick chain (8 commits, chronological):**

| Order | SHA | Tag | Subject | Upstream Author |
|-------|-----|-----|---------|-----------------|
| 1 | `7b58c3ee` | v0.43.0 | fix: set system-keyring as default feature for backward compatibility | Arnaud Sahuguet <sahuguet@users.noreply.github.com> |
| 2 | `f5215917` | v0.43.0 | feat: make system keyring optional for headless/container builds | Arnaud Sahuguet <sahuguet@users.noreply.github.com> |
| 3 | `1f912e53` | v0.43.0 | style: run cargo fmt | Arnaud Sahuguet <sahuguet@users.noreply.github.com> |
| 4 | `30c0f76e` | v0.43.0 | chore: release v0.43.0 | Luke Hinds <lukehinds@gmail.com> |
| 5 | `91476107` | v0.43.1 | fix(cli): char-aware truncation in truncate_command | Stephen Parkinson <scparkinson@gmail.com> |
| 6 | `e21e27d1` | v0.43.1 | fix(cli): shell-quote command args in display output (#660) | Stephen Parkinson <scparkinson@gmail.com> |
| 7 | `f4050670` | v0.43.1 | chore: release v0.43.1 | Luke Hinds <lukehinds@gmail.com> |
| 8 | `d38fe644` | v0.45.0 | chore: release v0.45.0 | Luke Hinds <lukehinds@gmail.com> |

Note: cluster ordering per DIVERGENCE-LEDGER.md (the cluster spans v0.43–v0.45 with no profile/policy/proxy-touching commits in v0.44 belonging to C5; `d38fe644` is the v0.45.0 release-bump that closes the cluster).

**D-19 trailer block (verbatim, paste per commit):**

```
Upstream-commit: {sha_abbrev_8char}
Upstream-tag: {tag}
Upstream-author: {author_name} <{author_email}>
Co-Authored-By: {author_name} <{author_email}>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

**Fork-divergence catalog cross-checks:**

- **Fork's Windows Credential Manager binding** (commit `77021c98` 2026-05-10: "fix(deps): enable keyring v3 windows-native backend (Credential Manager bypass)") is independent of `system-keyring` feature gating. After cherry-picking `7b58c3ee` + `f5215917`, verify that the Windows-native `keyring v3` backend is STILL enabled (`grep keyring crates/nono/Cargo.toml`).

- **MSI / headless install scenarios**: fork's MSI-installed Windows path runs as a service account with no interactive desktop session; the `system-keyring` opt-out path (`f5215917`) gives MSI installers a clean way to disable Credential Manager access at build-time.

**D-02 fallback gate** + **D-34-E1 per-commit invariant** + **per-commit commit body template** — same as Plan 34-01 (see § D-19 trailer block above + .planning/templates/upstream-sync-quick.md).
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Pre-flight — verify Plan 34-04 closed + capture pre-Plan-34-03 HEAD</name>
  <files>(git operations only)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-A2
  </read_first>
  <action>
    1. Verify Plan 34-04 closed (≥23 C7 v0.46/v0.47 commits on main).
    2. `git fetch upstream --tags`.
    3. Verify all 8 C5 SHAs reachable.
    4. Capture pre-Plan-34-03 HEAD SHA.
    5. Capture pre-Plan-34-03 keyring backend state:
       ```
       grep -A 5 'keyring' crates/nono/Cargo.toml
       # Record verbatim in SUMMARY § "Pre-state: keyring config"
       ```
    6. `cargo build --workspace` baseline green.
  </action>
  <verify>
    <automated>git fetch upstream --tags &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - Plan 34-04 closed; 8 C5 SHAs reachable; baseline build green; pre-state captured.
  </acceptance_criteria>
  <done>
    Ready for C5 chain.
  </done>
</task>

<task type="auto">
  <name>Task 2: Cherry-pick all 8 C5 commits with D-19 trailers</name>
  <files>
    crates/nono/Cargo.toml
    crates/nono/src/keystore.rs
    crates/nono-cli/src/audit_display.rs
    crates/nono-cli/src/audit_show.rs
    Cargo.lock
  </files>
  <read_first>
    - crates/nono/Cargo.toml § keyring dependency block (current `keyring v3 windows-native` config)
    - crates/nono/src/keystore.rs § feature-gated code paths
    - crates/nono-cli/src/audit_display.rs (current truncation + quoting logic)
    - `git show 7b58c3ee f5215917 1f912e53 30c0f76e 91476107 e21e27d1 f4050670 d38fe644 --stat`
  </read_first>
  <action>
    For each of the 8 commits, follow the per-commit pattern (cherry-pick + amend with D-19 trailer + D-34-E1 invariant check).

    **Critical attention point for commits 1-2:** `7b58c3ee` makes `system-keyring` the default feature; `f5215917` makes it optional. After commit 2, verify fork's Windows-native `keyring v3` backend (added 2026-05-10 in fork commit `77021c98`) is preserved:

    ```bash
    # After cherry-picking commit 2 (f5215917):
    grep -A 10 'keyring' crates/nono/Cargo.toml
    # MUST show:
    # - features include windows-native (fork addition; do NOT delete)
    # - default-features = false (fork's existing posture)
    # - features = ["windows-native", ...] (fork's existing list)
    # If the cherry-pick collapsed fork's windows-native into upstream's headless opt-out, RESTORE windows-native and re-amend the commit.
    ```

    **Critical attention point for commits 5-6:** `91476107` + `e21e27d1` touch `audit_display.rs` — fork's Phase 23 audit-show surface consumes this. After commit 6, verify:

    ```bash
    grep -c 'truncate_command\|shell_quote' crates/nono-cli/src/audit_display.rs
    # Expected: ≥ 2 (the new functions/uses)
    cargo test -p nono-cli audit_display::tests::
    # If fork has Phase 23 audit-display tests, they must still pass
    ```

    **Per-commit template** (commits 1-8):

    ```bash
    git cherry-pick <sha>
    cargo build --workspace
    git commit --amend -m "$(cat <<'EOF'
    <upstream subject verbatim>

    Upstream-commit: <8-char sha>
    Upstream-tag: <v0.43.0 | v0.43.1 | v0.45.0>
    Upstream-author: <name> <<email>>
    Co-Authored-By: <name> <<email>>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    After all 8:
    ```bash
    git log --format='%B' HEAD~8..HEAD | grep -c '^Upstream-commit: '   # Expected: 8
    git log --format='%B' HEAD~8..HEAD | grep -c 'Upstream-Author:'     # Expected: 0
    git log --format='%B' HEAD~8..HEAD | grep -c '^Signed-off-by: '     # Expected: 16

    # Smoke: Windows keyring still works (fork's windows-native preserved)
    cargo build --workspace
    grep 'windows-native' crates/nono/Cargo.toml | head -3   # Expected: at least 1 hit
    ```
  </action>
  <verify>
    <automated>git log --format='%B' HEAD~8..HEAD | grep -c '^Upstream-commit: ' | grep -E '^8$' &amp;&amp; cargo build --workspace &amp;&amp; grep -c 'windows-native' crates/nono/Cargo.toml</automated>
  </verify>
  <acceptance_criteria>
    - 8 commits with D-19 trailers (lowercase 'a').
    - `git log --format=%B HEAD~8..HEAD | grep -c '^Upstream-commit: '` returns `8`.
    - Per-commit D-34-E1 invariant returned 0.
    - `grep 'windows-native' crates/nono/Cargo.toml` returns ≥ 1 hit (fork's Credential Manager binding preserved).
    - Fork's audit-show tests pass.
  </acceptance_criteria>
  <done>
    C5 chain complete; Windows keyring binding preserved.
  </done>
</task>

<task type="auto">
  <name>Task 3: D-34-D2 close-gate (8 gates)</name>
  <files>(read-only verification)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-D2
  </read_first>
  <action>
    Run all 8 close-gates (test, 3× clippy, fmt, smoke, wfp, learn). Verify D-34-E1 invariant across the 8-commit chain.

    Additional Windows-specific check:
    ```bash
    # Sanity: keyring v3 with windows-native still resolves at runtime
    # (fork's Credential Manager bypass per 77021c98 / 2026-05-10)
    cargo build --workspace --features windows-native 2>&1 | grep -E 'error|warning: unused'
    # Expected: zero errors; warnings allowed only if pre-existing
    ```
  </action>
  <verify>
    <automated>cargo test --workspace --all-features &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo fmt --all -- --check</automated>
  </verify>
  <acceptance_criteria>
    - All 8 D-34-D2 gates pass (or documented-skip).
    - Windows keyring backend functional post-cluster (`windows-native` feature still active).
  </acceptance_criteria>
  <done>
    Plan 34-03 close-gate cleared.
  </done>
</task>

<task type="auto">
  <name>Task 4: Push + PR</name>
  <files>(git push only)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-D1
  </read_first>
  <action>
    1. `git fetch origin && git log main..origin/main --oneline | wc -l` — expect 0.
    2. `git push origin main`.
    3. Open PR: `gh pr create --title "Plan 34-03 (C5): Headless keyring + audit-display fixes (v0.43–v0.45, 8 commits)"` with the 8-gate checklist.
  </action>
  <verify>
    <automated>git fetch origin &amp;&amp; test "$(git log origin/main..main --oneline | wc -l)" = "0"</automated>
  </verify>
  <acceptance_criteria>
    - Pushed; PR opened.
  </acceptance_criteria>
  <done>
    Plan 34-03 published.
  </done>
</task>

</tasks>

<non_goals>
**No Windows Credential Manager binding removed.** Fork's commit `77021c98` (2026-05-10, `windows-native` keyring v3 backend) MUST survive. C5's `system-keyring` opt-out is composable with `windows-native`, not exclusive.

**No fork-only `keyring v3` API changes.** Cluster C5 absorbs upstream's `system-keyring` feature-flag work AS-IS.

**No `*_windows.rs` touched.**

**No MSI installer / service-account-side changes.** Plan 34-03 lands the build-time opt-out only; MSI integration to actually USE the opt-out is a separate decision.
</non_goals>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Process memory ↔ OS keystore | `keyring` crate crosses this boundary. Fork's `windows-native` backend uses Credential Manager directly. |
| Audit-event subject string ↔ display output | Display fixes (`91476107`, `e21e27d1`) sanitize untrusted command-args strings for terminal output. |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation |
|-----------|----------|-----------|----------|-------------|------------|
| T-34-03-01 | Tampering | D-21 Windows-only files invariant violation | **high** | mitigate (BLOCKING) | Per-commit D-34-E1 invariant. |
| T-34-03-02 | Repudiation | D-19 trailer block missing | **high** | mitigate (BLOCKING) | Task 2 plan-close smoke. |
| T-34-03-03 | Information Disclosure | Fork's `windows-native` keyring v3 backend silently dropped by cherry-pick (regression to default-`secret-service`-on-Windows; would fail on most Windows installs) | **high** | mitigate (BLOCKING) | Task 2 post-commit grep verifies `windows-native` feature still active in Cargo.toml. |
| T-34-03-04 | Tampering | Shell-quote display output (`e21e27d1`) introduces command-injection regression (escape escapes incorrectly) | medium | accept | Upstream's fix is reviewed-public; fork's audit-show tests run as a sentinel. |
| T-34-03-05 | Information Disclosure | Truncation (`91476107`) silently drops trailing content that contained security-relevant context (e.g., a denied-path string) | low | accept | Char-aware truncation preserves byte-level boundaries; truncation is a display concern, not a security control. |
| T-34-03-06 | Denial of Service | Headless build with `--no-default-features` fails at runtime because no keyring backend resolves | low | mitigate | `keystore.rs` must fail-closed with a clear error message when no backend is available (existing keyring v3 behavior; fork-side tests cover this). |
</threat_model>

<verification>
- All 8 D-34-D2 close-gates pass.
- `git log --format='%B' HEAD~8..HEAD | grep -c '^Upstream-commit: '` returns `8`.
- `git log --format='%B' HEAD~8..HEAD | grep -c '^Signed-off-by: '` returns `16`.
- Per-commit D-34-E1 invariant: 0 hits across all 8 commits.
- `grep 'windows-native' crates/nono/Cargo.toml` returns ≥ 1 hit.
- `cargo build --workspace --features windows-native` exits 0.
</verification>

<success_criteria>
- 8 atomic commits on `main`, each with D-19 trailer.
- `system-keyring` default-on; opt-out path for headless/container builds available.
- Fork's `windows-native` keyring v3 backend preserved.
- Audit-display fixes (char-aware truncation + shell-quote) landed.
- All 8 D-34-D2 gates green.
- `origin/main` advanced; PR opened.
</success_criteria>

<output>
After completion, create `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-03-SUMMARY.md`.
</output>
