---
phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
plan_number: 34-05
plan: 05
slug: completion
cluster_id: C8
type: execute
wave: 2
depends_on: ["34-04", "34-01"]
blocks: []
files_modified:
  - crates/nono-cli/src/cli.rs
  - crates/nono-cli/src/main.rs
  - crates/nono-cli/src/string_truncation.rs
  - crates/nono-cli/src/profile/mod.rs
upstream_tag_range: v0.48.0
upstream_commit_count: 8
autonomous: true
requirements: [C8]
tags: [upst3, c8, completion, string-truncation, wave-2]

must_haves:
  truths:
    - "All 8 cluster-C8 commits cherry-picked onto `main` in upstream chronological order"
    - "Every Plan 34-05 commit body carries the verbatim D-19 6-line trailer block"
    - "`nono completion <shell>` subcommand exists (`03546d61`); supports bash/zsh/fish/powershell verbatim from upstream"
    - "D-34-B2 surgical posture: `nono completion` is shipped AS-IS; NO MSI integration; NO PowerShell `$PROFILE.d/` shim"
    - "Truncation panic fix (`4b353549`) + string-truncation utility refactor (`7b71855c`) landed"
    - "Skip self-references in sibling extends (`e4e73e1b`); demote --allow-launch-services log (`f2592a2b`); cleanup unused code (`30245dbb`); reduce nono run output verbosity (`777dd95d`)"
    - "D-34-E1 invariant: zero edits to `*_windows.rs` for every commit"
    - "All 8 D-34-D2 close-gates pass"
  artifacts:
    - path: "crates/nono-cli/src/cli.rs"
      provides: "`nono completion <shell>` subcommand (`03546d61`)"
      grep_pattern: "Completion|completion.*shell"
    - path: "crates/nono-cli/src/string_truncation.rs"
      provides: "Extracted string-truncation utility (`7b71855c`); panic fix (`4b353549`)"
      grep_pattern: "truncate"
  key_links:
    - from: "User running `nono completion powershell > $PROFILE.d/nono.ps1`"
      to: "clap-generated completion output"
      via: "manual user step per D-34-B2; NO MSI integration"
      pattern: "Completion.*shell|completion.*Shell"
---

<objective>
Cluster C8 (upstream v0.48.0, 8 commits): `nono completion <shell>` subcommand + truncation panic fix + string-truncation utility refactor.

**Critical D-34-B2 posture:** Ship the subcommand verbatim from upstream `03546d61`. NO MSI installer integration; NO PowerShell `$PROFILE.d/` shim. Users on Windows run `nono completion powershell > $PROFILE.d/nono.ps1` manually (one-line cookbook entry sufficient). MSI integration deferred per Phase 34 Deferred Ideas.

Output: 8 atomic commits with D-19 trailers; surgical posture documented in commit body for `03546d61`.
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
@crates/nono-cli/src/cli.rs

<interfaces>
**Cluster C8 cherry-pick chain (8 commits, chronological):**

| Order | SHA | Tag | Subject | Upstream Author |
|-------|-----|-----|---------|-----------------|
| 1 | `03546d61` | v0.48.0 | feat(cli): add shell completion generation via `nono completion <shell>` | Mark Sisson <5761292+marksisson@users.noreply.github.com> |
| 2 | `30245dbb` | v0.48.0 | cleanup unused code | SequeI <asiek@redhat.com> |
| 3 | `4b353549` | v0.48.0 | fix(cli): prevent truncate_chars panic and spurious truncation | Luke Hinds <lukehinds@gmail.com> |
| 4 | `777dd95d` | v0.48.0 | chore: reduce nono run output verbosity | SequeI <asiek@redhat.com> |
| 5 | `7b71855c` | v0.48.0 | refactor(string-truncation): extract generic string truncation utility | Luke Hinds <lukehinds@gmail.com> |
| 6 | `e4e73e1b` | v0.48.0 | fix(profile): skip self-references in sibling extends resolution | SequeI <asiek@redhat.com> |
| 7 | `f2592a2b` | v0.48.0 | fix: demote --allow-launch-services log from warn to debug | SequeI <asiek@redhat.com> |
| 8 | `e15b9c46` | v0.48.0 | chore: release v0.48.0 | Luke Hinds <lukehinds@gmail.com> |

**Plan ordering note:** Plan 34-05 follows Plan 34-02 in Wave 2 chronologically (C4 v0.42-v0.45 < C8 v0.48). Both touch `cli.rs`; ensure Plan 34-02's commits land first to keep `cli.rs` in upstream chronological order.

**D-34-B2 commit-body specifics for `03546d61`:**

```
feat(cli): add shell completion generation via `nono completion <shell>`

Per Phase 34 D-34-B2 surgical retrofit posture: shipped AS-IS from upstream.
NO MSI installer integration. NO PowerShell $PROFILE.d/ shim. Users on
Windows run `nono completion powershell > $PROFILE.d/nono.ps1` manually
(one-line cookbook entry). MSI integration deferred per Phase 34
Deferred Ideas.

Upstream-commit: 03546d61
Upstream-tag: v0.48.0
Upstream-author: Mark Sisson <5761292+marksisson@users.noreply.github.com>
Co-Authored-By: Mark Sisson <5761292+marksisson@users.noreply.github.com>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

**Fork-divergence catalog:**

- `crates/nono-cli/src/audit_display.rs` (touched in C5 cluster Plan 34-03) may overlap with C8's `string-truncation` refactor (`7b71855c`). After Plan 34-03 lands, C8's refactor moves shared truncation helpers from `audit_display.rs` into the new `string_truncation.rs` module — verify Plan 34-03's char-aware truncation (`91476107`) survives the move.
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Pre-flight — verify Plan 34-04 + Plan 34-01 closed; capture cli.rs state</name>
  <files>(git operations only)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-A2 + D-34-B2
  </read_first>
  <action>
    1. Verify Plan 34-04 + Plan 34-01 closed.
    2. `git fetch upstream --tags`.
    3. Verify all 8 C8 SHAs reachable.
    4. Capture pre-Plan-34-05 HEAD; capture `cli.rs` `Commands::` enum variant list:
       ```
       grep -E '^    [A-Z][a-zA-Z]+\(' crates/nono-cli/src/cli.rs | head -30
       # Record in SUMMARY § "Pre-state: Commands enum"
       ```
    5. `cargo build --workspace`.
  </action>
  <verify>
    <automated>git fetch upstream --tags &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - Plans 34-04 + 34-01 closed; 8 SHAs reachable; baseline green.
  </acceptance_criteria>
  <done>
    Ready for C8 chain.
  </done>
</task>

<task type="auto">
  <name>Task 2: Cherry-pick all 8 C8 commits with D-19 trailers + surgical-posture note for 03546d61</name>
  <files>
    crates/nono-cli/src/cli.rs
    crates/nono-cli/src/main.rs
    crates/nono-cli/src/string_truncation.rs
    crates/nono-cli/src/profile/mod.rs
  </files>
  <read_first>
    - crates/nono-cli/src/cli.rs § post-Plan-34-01 + post-Plan-34-02 `Commands` enum
    - crates/nono-cli/src/audit_display.rs § post-Plan-34-03 truncation logic (may move in `7b71855c`)
    - `git show 03546d61 30245dbb 4b353549 777dd95d 7b71855c e4e73e1b f2592a2b e15b9c46 --stat`
  </read_first>
  <action>
    For each of the 8 commits, follow the per-commit pattern. Specifics:

    **Commit 1/8: `03546d61` (Mark Sisson, "feat(cli): add shell completion generation via `nono completion <shell>`") — D-34-B2 SURGICAL POSTURE COMMIT:**

    Use the surgical-posture commit body from `<interfaces>`.

    After cherry-pick, verify NO MSI integration:
    ```bash
    grep -rE 'completion.*msi|msi.*completion' crates/   # Expected: 0
    grep -rE 'PROFILE\.d|\$PROFILE\\\.d' crates/         # Expected: 0
    ```

    **Commit 5/8: `7b71855c` (Luke Hinds, "refactor(string-truncation): extract generic string truncation utility"):**

    Moves shared truncation helpers into new `string_truncation.rs` module. After cherry-pick, verify Plan 34-03's char-aware truncation behavior is preserved (test it):
    ```bash
    grep -c 'truncate' crates/nono-cli/src/string_truncation.rs   # Expected: ≥ 1
    cargo test -p nono-cli audit_display::tests::   # Plan 34-03's tests still pass
    cargo test -p nono-cli string_truncation::tests::   # New tests from C8 pass
    ```

    **Per-commit template:**

    ```bash
    git cherry-pick <sha>
    cargo build --workspace
    git commit --amend -m "$(cat <<'EOF'
    <upstream subject verbatim>

    Upstream-commit: <8-char sha>
    Upstream-tag: v0.48.0
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
    git log --format='%B' HEAD~8..HEAD | grep -c '^Signed-off-by: '     # Expected: 16

    # Smoke test: completion works on Windows
    cargo run --quiet --bin nono -- completion powershell 2>&1 | head -10
    # Expected: PowerShell completion script output (at least 5 lines)
    ```
  </action>
  <verify>
    <automated>git log --format='%B' HEAD~8..HEAD | grep -c '^Upstream-commit: ' | grep -E '^8$' &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - 8 commits with D-19 trailers (lowercase 'a').
    - Per-commit D-34-E1 invariant returned 0.
    - `nono completion powershell` exits 0 with PowerShell completion script output.
    - `nono completion bash` exits 0 with Bash completion script output.
    - No MSI / `$PROFILE.d/` integration in any source file (D-34-B2 verified).
    - Plan 34-03's audit_display tests still pass post-refactor.
  </acceptance_criteria>
  <done>
    C8 chain complete; completion subcommand functional; surgical posture preserved.
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
    Plan 34-05 close-gate cleared.
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
    2. `gh pr create --title "Plan 34-05 (C8): nono completion + string-truncation refactor (v0.48.0, 8 commits)"`.
  </action>
  <verify>
    <automated>git fetch origin &amp;&amp; test "$(git log origin/main..main --oneline | wc -l)" = "0"</automated>
  </verify>
  <acceptance_criteria>
    - Pushed; PR opened.
  </acceptance_criteria>
  <done>
    Plan 34-05 published.
  </done>
</task>

</tasks>

<non_goals>
**D-34-B2 surgical posture — `nono completion` shipped AS-IS.** No MSI installer integration. No `$PROFILE.d/` shim. Users run the completion-emission manually.

**No `*_windows.rs` touched.**

**No fork-only completion logic.** Upstream's clap-driven generator handles bash, zsh, fish, PowerShell, elvish out of the box; fork ships them all.
</non_goals>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| User shell environment ← `nono completion` output | The generated completion script runs in the user's shell. Standard shell-completion trust model: user-owned process; same trust level as the user's profile. |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation |
|-----------|----------|-----------|----------|-------------|------------|
| T-34-05-01 | Tampering | D-21 Windows-only files invariant violation | **high** | mitigate (BLOCKING) | Per-commit D-34-E1 invariant. |
| T-34-05-02 | Repudiation | D-19 trailer missing | **high** | mitigate (BLOCKING) | Task 2 smoke. |
| T-34-05-03 | Tampering | Truncation refactor (`7b71855c`) accidentally drops Plan 34-03's char-aware truncation behavior | medium | mitigate | Task 2 verifies `cargo test -p nono-cli audit_display::tests::` post-refactor. |
| T-34-05-04 | Information Disclosure | Truncation panic fix (`4b353549`) leaks original (untruncated) string into the panic message | low | accept | Upstream's fix prevents the panic, not the panic-message exposure (panic messages shouldn't reach untrusted output paths in any case). |
| T-34-05-05 | Spoofing | Generated completion script contains hardcoded paths that differ between dev and MSI install | low | accept | Clap completion generation uses `$0`-style invocation, not hardcoded paths. |
| T-34-05-06 | Denial of Service | `f2592a2b` log demotion silently drops a security-relevant warning into debug-level output | low | mitigate | Upstream's reasoning: `--allow-launch-services` is macOS-side, not security-critical-on-Windows; debug level is appropriate. |
</threat_model>

<verification>
- All 8 D-34-D2 close-gates pass.
- `git log --format='%B' HEAD~8..HEAD | grep -c '^Upstream-commit: '` returns `8`.
- Per-commit D-34-E1 invariant: 0 hits.
- `nono completion powershell` exits 0 with PowerShell script output.
- `grep -rE 'completion.*msi|PROFILE\\.d' crates/` returns 0 (D-34-B2 verified).
</verification>

<success_criteria>
- 8 atomic commits on `main`, each with D-19 trailer.
- `nono completion <shell>` subcommand functional for bash/zsh/fish/powershell.
- D-34-B2 surgical posture preserved (no MSI integration).
- Plan 34-03's char-aware truncation behavior survives string-truncation refactor.
- All 8 D-34-D2 gates green.
- `origin/main` advanced; PR opened.
</success_criteria>

<output>
After completion, create `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-05-SUMMARY.md`.
</output>
