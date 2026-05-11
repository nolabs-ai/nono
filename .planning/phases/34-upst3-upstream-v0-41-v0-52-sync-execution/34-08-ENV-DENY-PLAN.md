---
phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
plan_number: 34-08
plan: 08
slug: env-deny
cluster_id: C12
type: execute
wave: 2
depends_on: ["34-04", "34-01", "34-02", "34-05", "34-07"]
blocks: []
files_modified:
  - crates/nono-cli/src/cli.rs
  - crates/nono-cli/src/exec_strategy/env_sanitization.rs
  - crates/nono-cli/src/profile/mod.rs
  - crates/nono-cli/src/learn.rs
  - crates/nono-cli/src/diagnostic.rs
  - crates/nono/src/capability.rs
upstream_tag_range: v0.52.0
upstream_commit_count: 10
autonomous: true
requirements: [C12]
tags: [upst3, c12, env, deny-vars, learn-deprecation, wave-2]

must_haves:
  truths:
    - "All 10 cluster-C12 commits cherry-picked onto `main` in upstream chronological order"
    - "Every Plan 34-08 commit body carries the verbatim D-19 6-line trailer block"
    - "Operator-controlled `deny_vars` added to `EnvironmentConfig` (`3657c935`); fail-closed semantics for empty `allow_vars` preserved (`780965d7`); `matches_env_var_patterns` helper extracted (`a022e5c7`)"
    - "`nono learn` deprecation message lands in `cli.rs` (`b34c2af6`); D-34-B2 surgical posture: `learn_windows.rs` stays byte-identical"
    - "macOS learn diagnostics enhanced (`b5f0a3ab`, `bbdf7b85`, `f782ddcd`) — macOS-only paths, fork inherits"
    - "D-34-E1 invariant: zero edits to `*_windows.rs` for every commit"
    - "All 8 D-34-D2 close-gates pass"
    - "D-34-B2 surgical posture: `learn_windows.rs` last-touched SHA UNCHANGED post-Plan-34-08"
  artifacts:
    - path: "crates/nono-cli/src/exec_strategy/env_sanitization.rs"
      provides: "`deny_vars` operator-controlled env list (`3657c935`); fail-closed empty-allow semantics (`780965d7`); `matches_env_var_patterns` helper (`a022e5c7`)"
      grep_pattern: "deny_vars|matches_env_var_patterns"
    - path: "crates/nono-cli/src/cli.rs"
      provides: "`nono learn` deprecation message (`b34c2af6`)"
      grep_pattern: "learn.*deprecat|deprecat.*learn"
  key_links:
    - from: "User running `nono learn` (cross-platform)"
      to: "Deprecation message stderr output"
      via: "single cross-platform deprecation message; `learn_windows.rs` (D-11 excluded; ETW path) stays byte-identical per D-34-B2"
      pattern: "learn.*deprecated|nono learn.*replaced"
    - from: "Operator-defined `deny_vars: ['AWS_*', 'GITHUB_TOKEN']`"
      to: "`env_sanitization::sanitize_env`"
      via: "fail-closed filter applied at exec-time before child process spawn"
      pattern: "deny_vars.*sanitize|sanitize.*deny_vars"
---

<objective>
Cluster C12 (upstream v0.52.0, 10 commits): operator-controlled `deny_vars` in `EnvironmentConfig` + `nono learn` deprecation + macOS learn diagnostics. The deny_vars + fail-closed-on-empty-allow correctness fixes are the security-relevant items; the learn deprecation is a CLI surface alignment item; macOS learn diagnostics ride along (macOS-only paths).

**Critical D-34-B2 posture:** `nono learn` deprecation message flows through `cli.rs` unchanged from upstream `b34c2af6`. `learn_windows.rs` (D-11 excluded; ETW path) stays byte-identical. No Windows-specific deprecation docstring addition.

Output: 10 atomic commits with D-19 trailers; D-34-B2 surgical posture verified.
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
@crates/nono-cli/src/exec_strategy/env_sanitization.rs

<interfaces>
**Cluster C12 cherry-pick chain (10 commits, chronological per upstream topology):**

| Order | SHA | Tag | Subject | Upstream Author |
|-------|-----|-----|---------|-----------------|
| 1 | `1d491b4d` | v0.52.0 | style: run cargo fmt | Advaith Sujith <advaith@alwaysfurther.ai> |
| 2 | `3657c935` | v0.52.0 | feat(env): add operator-controlled deny_vars to EnvironmentConfig | Advaith Sujith <advaith@alwaysfurther.ai> |
| 3 | `780965d7` | v0.52.0 | fix(env): preserve fail-closed semantics for empty allow_vars | Advaith Sujith <advaith@alwaysfurther.ai> |
| 4 | `a022e5c7` | v0.52.0 | refactor(env): extract matches_env_var_patterns helper, fix docs wording | Advaith Sujith <advaith@alwaysfurther.ai> |
| 5 | `b34c2af6` | v0.52.0 | feat(cli): deprecate 'nono learn' and improve diagnostics | Luke Hinds <lukehinds@gmail.com> |
| 6 | `b5f0a3ab` | v0.52.0 | feat(cli): enhance macos learn and run diagnostics | Luke Hinds <lukehinds@gmail.com> |
| 7 | `bbdf7b85` | v0.52.0 | fix(diagnostic): parse escaped quotes in structured properties | Luke Hinds <lukehinds@gmail.com> |
| 8 | `f782ddcd` | v0.52.0 | feat(cli): enhance interactive experience and profile saving | Luke Hinds <lukehinds@gmail.com> |
| 9 | `31f2fc27` | v0.52.0 | fix(lint): replace unwrap() with is_some_and() in test | Advaith Sujith <advaith@alwaysfurther.ai> |
| 10 | `5d15b50e` | v0.52.0 | chore: release v0.52.0 | Luke Hinds <lukehinds@gmail.com> |

**Note:** Cluster ordering per DIVERGENCE-LEDGER.md; the exact chronological order within v0.52.0 should be verified via `git log --topo-order upstream/v0.51.0..upstream/v0.52.0` before cherry-picking.

**D-34-B2 commit-body specifics for `b34c2af6`:**

```
feat(cli): deprecate 'nono learn' and improve diagnostics

Per Phase 34 D-34-B2 surgical retrofit posture: deprecation message flows
through cli.rs unchanged from upstream. learn_windows.rs (D-11 excluded;
ETW path) stays BYTE-IDENTICAL. No Windows-specific deprecation docstring
addition. User-visible stderr message is sufficient cross-platform.

Upstream-commit: b34c2af6
Upstream-tag: v0.52.0
Upstream-author: Luke Hinds <lukehinds@gmail.com>
Co-Authored-By: Luke Hinds <lukehinds@gmail.com>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

**Fork-divergence catalog:**

- **`learn_windows.rs` byte-identical preservation** (D-11 + D-34-B2): per-commit verify
  ```
  git diff --stat HEAD~1 HEAD -- crates/nono-cli/src/learn_windows.rs | wc -l   # Expected: 0
  ```
  AND at plan close:
  ```
  git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs
  # Must equal the pre-Plan-34-08 SHA captured in Task 1
  ```

- **Phase 20 UPST-03 env_sanitization port**: fork already ports upstream's `env_sanitization.rs` shape. The new `deny_vars` field + `matches_env_var_patterns` helper compose with the existing surface — verify the new patterns work alongside fork's existing `allow_vars` + fail-closed semantics.

- **CRITICAL audit finding from Phase 33** (DIVERGENCE-LEDGER.md § Cluster C12 "Audit finding"): the v0.52.0 cluster does NOT contain any RESL flag rename commits. G-25-DRIFT-01 was closed in Plan 34-00 as no-divergence. Plan 34-08 must NOT introduce RESL-flag renames — confirm by re-grep:
  ```
  grep -rE 'memory.*deprecated|cpu-percent.*deprecated|max-processes.*deprecated|timeout.*deprecated' crates/   # Expected: 0
  ```
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Pre-flight — verify Plans 34-04, 34-01, 34-02, 34-05, 34-07 closed; capture learn_windows.rs SHA</name>
  <files>(git operations only)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-A2 + D-34-B2
    - crates/nono-cli/src/learn_windows.rs (read first lines to confirm fork-only Phase 11 ETW path)
  </read_first>
  <action>
    1. Verify all dependent plans closed.
    2. `git fetch upstream --tags`.
    3. Verify all 10 C12 SHAs reachable.
    4. **CRITICAL** Capture pre-Plan-34-08 `learn_windows.rs` last-touched SHA (D-34-B2 anchor):
       ```
       git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs
       # Record verbatim in SUMMARY § "Pre-state: learn_windows.rs SHA"
       # This SHA MUST be unchanged at plan close
       ```
    5. Capture pre-Plan-34-08 HEAD; `cargo build --workspace` baseline.
  </action>
  <verify>
    <automated>git fetch upstream --tags &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - All dependent plans closed; 10 SHAs reachable; pre-state `learn_windows.rs` SHA captured.
  </acceptance_criteria>
  <done>
    Ready for C12 chain.
  </done>
</task>

<task type="auto">
  <name>Task 2: Cherry-pick all 10 C12 commits with D-19 trailers + surgical-posture note for b34c2af6</name>
  <files>
    crates/nono-cli/src/cli.rs
    crates/nono-cli/src/exec_strategy/env_sanitization.rs
    crates/nono-cli/src/profile/mod.rs
    crates/nono-cli/src/learn.rs
    crates/nono-cli/src/diagnostic.rs
    crates/nono/src/capability.rs
  </files>
  <read_first>
    - crates/nono-cli/src/exec_strategy/env_sanitization.rs § current allow_vars/deny_vars shape (Phase 20 UPST-03)
    - crates/nono-cli/src/cli.rs § `Commands::Learn` (where deprecation message lands)
    - crates/nono-cli/src/learn_windows.rs (read first 20 lines — fork-only ETW path; must stay byte-identical)
    - `git show 1d491b4d 3657c935 780965d7 a022e5c7 b34c2af6 b5f0a3ab bbdf7b85 f782ddcd 31f2fc27 5d15b50e --stat`
  </read_first>
  <action>
    For each of the 10 commits, follow the per-commit pattern. Specifics:

    **Commit 2/10: `3657c935` (Advaith Sujith, "feat(env): add operator-controlled deny_vars to EnvironmentConfig"):**

    After cherry-pick, verify deny_vars composes with existing allow_vars:
    ```bash
    cargo test -p nono-cli env_sanitization::tests::
    grep -c 'deny_vars' crates/nono-cli/src/exec_strategy/env_sanitization.rs   # Expected: ≥ 1
    ```

    **Commit 3/10: `780965d7` (Advaith Sujith, "fix(env): preserve fail-closed semantics for empty allow_vars"):**

    Security fix. After cherry-pick, verify fail-closed test passes:
    ```bash
    cargo test -p nono-cli env_sanitization::tests::empty_allow_fails_closed
    ```

    **Commit 5/10: `b34c2af6` (Luke Hinds, "feat(cli): deprecate 'nono learn' and improve diagnostics") — D-34-B2 SURGICAL POSTURE COMMIT:**

    Use the surgical-posture commit body from `<interfaces>`. After cherry-pick, verify `learn_windows.rs` is untouched:
    ```bash
    git diff --stat HEAD~1 HEAD -- crates/nono-cli/src/learn_windows.rs | wc -l   # Expected: 0
    grep -c 'deprecat' crates/nono-cli/src/cli.rs   # Expected: ≥ 1 (new deprecation message)
    grep -c 'deprecat' crates/nono-cli/src/learn_windows.rs   # Expected: same as pre-Plan baseline (likely 0)
    ```

    **Commit 6/10: `b5f0a3ab` (Luke Hinds, "feat(cli): enhance macos learn and run diagnostics"):**

    9-file change. Mostly macOS-only paths. Verify after cherry-pick:
    ```bash
    cargo build --workspace --target x86_64-apple-darwin   # macOS gates compile
    cargo build --workspace                                # Windows baseline still green
    ```

    **Critical anti-regression check for G-25-DRIFT-01:**

    After all 10 commits, verify NO RESL flag rename appeared:
    ```bash
    # G-25-DRIFT-01 closed Plan 34-00 as no-divergence. Confirm no rename surface introduced:
    grep -rE 'memory.*deprecat|cpu-percent.*deprecat|max-processes.*deprecat' crates/   # Expected: 0
    # The closure rationale was empirical (upstream v0.52.0 still ships --memory etc.); a rename appearing here would indicate either upstream churned post-audit OR a cherry-pick bug.
    ```

    **Per-commit template:**

    ```bash
    git cherry-pick <sha>
    cargo build --workspace
    git commit --amend -m "$(cat <<'EOF'
    <upstream subject verbatim>

    Upstream-commit: <8-char sha>
    Upstream-tag: v0.52.0
    Upstream-author: <name> <<email>>
    Co-Authored-By: <name> <<email>>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    git diff --stat HEAD~1 HEAD -- crates/nono-cli/src/learn_windows.rs | wc -l   # Expected: 0 (per-commit)
    ```

    After all 10:
    ```bash
    git log --format='%B' HEAD~10..HEAD | grep -c '^Upstream-commit: '   # Expected: 10
    git log --format='%B' HEAD~10..HEAD | grep -c '^Signed-off-by: '     # Expected: 20

    # D-34-B2 anchor verification:
    git log -1 --format='%H' -- crates/nono-cli/src/learn_windows.rs
    # MUST equal pre-Plan-34-08 SHA from Task 1
    ```
  </action>
  <verify>
    <automated>git log --format='%B' HEAD~10..HEAD | grep -c '^Upstream-commit: ' | grep -E '^10$' &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - 10 commits with D-19 trailers (lowercase 'a').
    - Per-commit D-34-E1 invariant returned 0.
    - Per-commit `learn_windows.rs` diff = 0 (byte-identical preservation).
    - `grep -c 'deny_vars' crates/nono-cli/src/exec_strategy/env_sanitization.rs` returns ≥ 1.
    - Empty-allow fail-closed test passes.
    - `nono learn` invocation prints deprecation message to stderr.
    - No RESL flag rename introduced (G-25-DRIFT-01 closure invariant preserved).
    - `learn_windows.rs` last-touched SHA equals Task 1 baseline.
  </acceptance_criteria>
  <done>
    C12 chain complete; D-34-B2 surgical posture verified.
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

    Special attention to Gate 8 (learn_windows_integration): verify the ETW path still functions despite the cross-platform deprecation message.
    ```bash
    cargo test -p nono-cli --test learn_windows_integration
    ```
  </action>
  <verify>
    <automated>cargo test --workspace --all-features &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo fmt --all -- --check &amp;&amp; cargo test -p nono-cli --test learn_windows_integration</automated>
  </verify>
  <acceptance_criteria>
    - All 8 close-gates pass.
    - `learn_windows_integration` exits 0 (ETW path functional despite cross-platform deprecation message).
  </acceptance_criteria>
  <done>
    Plan 34-08 close-gate cleared.
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
    2. `gh pr create --title "Plan 34-08 (C12): env deny_vars + nono learn deprecation + macOS diagnostics (v0.52.0, 10 commits)"`.
  </action>
  <verify>
    <automated>git fetch origin &amp;&amp; test "$(git log origin/main..main --oneline | wc -l)" = "0"</automated>
  </verify>
  <acceptance_criteria>
    - Pushed; PR opened.
  </acceptance_criteria>
  <done>
    Plan 34-08 published. Wave 2 complete.
  </done>
</task>

</tasks>

<non_goals>
**D-34-B2 surgical posture — `learn_windows.rs` byte-identical.** Per-commit diff against `learn_windows.rs` MUST be empty. No deprecation docstring addition to the ETW path.

**No RESL flag rename.** G-25-DRIFT-01 was closed Plan 34-00 as no-divergence; Plan 34-08 must not introduce a rename.

**No `*_windows.rs` touched.**

**No `learn` subcommand removal.** Deprecation message lands; the subcommand still functions cross-platform.

**No env_sanitization rewrite.** `deny_vars` extension composes with existing Phase 20 UPST-03 surface.
</non_goals>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Operator-defined deny_vars list → exec-time env filter | New configuration primitive; fail-closed required. |
| Child process env vars ← sanitized parent env | The sanitization filter crosses the supervisor/child boundary. |
| Diagnostic structured properties parser → terminal output | `bbdf7b85` parses escaped quotes; injection vector. |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation |
|-----------|----------|-----------|----------|-------------|------------|
| T-34-08-01 | Tampering | D-21 Windows-only files invariant violation | **high** | mitigate (BLOCKING) | Per-commit D-34-E1 invariant. |
| T-34-08-02 | Tampering | D-34-B2 surgical-posture violation — `learn_windows.rs` modified by cluster cherry-pick | **high** | mitigate (BLOCKING) | Per-commit + plan-close `git diff --stat HEAD~1 HEAD -- crates/nono-cli/src/learn_windows.rs` returns 0. |
| T-34-08-03 | Repudiation | D-19 trailer missing | **high** | mitigate (BLOCKING) | Task 2 smoke. |
| T-34-08-04 | Information Disclosure | `780965d7` empty-allow regression — empty `allow_vars` accidentally treated as allow-all (instead of fail-closed) | **high** | mitigate (BLOCKING) | Task 2 verifies `empty_allow_fails_closed` test passes. Phase 20 UPST-03's existing test infrastructure covers this. |
| T-34-08-05 | Elevation of Privilege | `deny_vars` pattern matcher (`a022e5c7`) has glob-expansion bug allowing accidental allowlist (e.g., `AWS_*` glob escapes) | medium | mitigate | Task 2 runs `cargo test -p nono-cli env_sanitization::tests::` — fork's existing env-pattern tests cover boundary cases. |
| T-34-08-06 | Tampering | `bbdf7b85` escaped-quote parser introduces injection vector via malformed structured property | low | accept | Upstream's fix is for display-side parsing; standard nono CLI output redaction applies. |
| T-34-08-07 | Repudiation | Cross-platform deprecation message routed to ETW Windows surface, breaking ETW event-stream consumers | low | mitigate | D-34-B2 surgical posture verified: `learn_windows.rs` untouched; deprecation message goes to stderr, not ETW. |
</threat_model>

<verification>
- All 8 D-34-D2 close-gates pass.
- `git log --format='%B' HEAD~10..HEAD | grep -c '^Upstream-commit: '` returns `10`.
- Per-commit D-34-E1 invariant: 0 hits.
- Per-commit `learn_windows.rs` diff = 0; plan-close `learn_windows.rs` SHA unchanged from Task 1 baseline.
- `grep -c 'deny_vars' crates/nono-cli/src/exec_strategy/env_sanitization.rs` returns ≥ 1.
- `empty_allow_fails_closed` test passes.
- `nono learn` invocation emits deprecation message to stderr.
- No RESL flag rename introduced.
- `cargo test -p nono-cli --test learn_windows_integration` exits 0.
</verification>

<success_criteria>
- 10 atomic commits on `main`, each with D-19 trailer.
- `deny_vars` operator-controlled env list landed; fail-closed empty-allow semantics preserved.
- `nono learn` deprecation message landed cross-platform; `learn_windows.rs` byte-identical.
- macOS learn diagnostics enhanced.
- D-34-B2 surgical posture verified.
- All 8 D-34-D2 gates green.
- `origin/main` advanced; PR opened.
- Wave 2 complete; Wave 3 (Plans 34-09, 34-10 manual replays) unblocked.
</success_criteria>

<output>
After completion, create `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-08-SUMMARY.md`.
</output>
