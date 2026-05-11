---
phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
plan_number: 34-01
plan: 01
slug: cli-consolidation
cluster_id: C2
type: execute
wave: 1
depends_on: ["34-04"]
blocks: []
files_modified:
  - crates/nono-cli/src/cli.rs
  - crates/nono-cli/src/profile/mod.rs
  - crates/nono-cli/src/policy.rs
  - crates/nono-cli/src/main.rs
upstream_tag_range: v0.41.0
upstream_commit_count: 6
autonomous: true
requirements: [C2]
tags: [upst3, c2, cli, profile, policy, wave-1]

must_haves:
  truths:
    - "All 6 cluster-C2 commits cherry-picked onto `main` in upstream chronological order"
    - "Every Plan 34-01 commit body carries the verbatim D-19 6-line trailer block"
    - "`nono profile` subcommand tree exists; `nono policy` deprecation alias forwards to `nono profile` with a deprecation message"
    - "Denial-diagnostic output enhanced per `034be703` + `77bbe42a`; user-facing CLI surface aligned with upstream v0.41"
    - "Smoke check: `git log --format='%B' HEAD~6..HEAD | grep -c '^Upstream-commit: '` equals 6"
    - "D-34-E1 invariant: zero edits to `*_windows.rs` for every commit"
    - "All 8 D-34-D2 close-gates pass"
  artifacts:
    - path: "crates/nono-cli/src/cli.rs"
      provides: "`nono profile` subcommand tree with deprecation alias from `nono policy`; enhanced denial-diagnostic output"
      grep_pattern: "Profile\\(ProfileArgs\\)|nono profile|deprecation"
    - path: "crates/nono-cli/src/profile/mod.rs"
      provides: "Resilient profile save (`87758af1`); enhanced denial diagnostics integration (`034be703`)"
      grep_pattern: "save_profile|denial_diagnostic"
    - path: "crates/nono-cli/src/main.rs"
      provides: "Startup-prompt function extraction (`37488ce0`)"
      grep_pattern: "startup_prompt|cli_startup_prompt"
  key_links:
    - from: "User running `nono policy <args>` (legacy invocation)"
      to: "`nono profile <args>` (new canonical subcommand)"
      via: "deprecation alias with one-release transition window"
      pattern: "alias.*policy|deprecat.*policy"
---

<objective>
Cluster C2 (upstream v0.41.0, 6 commits): consolidate the `nono policy` subcommand tree under `nono profile` with deprecation aliases, plus enhance denial diagnostics and profile-save resilience. User-facing CLI surface alignment with upstream — same justification class as G-25-DRIFT-01 (CLI surface match).

Output: 6 atomic commits on `main`, each with D-19 trailer. `nono profile` becomes the canonical surface; `nono policy` invocations continue to work via deprecation alias for one release.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@CLAUDE.md
@.planning/STATE.md
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md
@.planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md
@.planning/templates/upstream-sync-quick.md
@crates/nono-cli/src/cli.rs
@crates/nono-cli/src/profile/mod.rs
@crates/nono-cli/src/main.rs

<interfaces>
**Cluster C2 cherry-pick chain (6 commits, chronological):**

| Order | SHA | Tag | Subject | Upstream Author |
|-------|-----|-----|---------|-----------------|
| 1 | `034be703` | v0.41.0 | feat(cli): improve denial diagnostics and profile saving workflow | Luke Hinds <lukehinds@gmail.com> |
| 2 | `37488ce0` | v0.41.0 | refactor(cli-startup-prompt): extract startup prompt functions | Luke Hinds <lukehinds@gmail.com> |
| 3 | `5ff9bc33` | v0.41.0 | feat(cli): consolidate 'nono policy' subcommands under 'nono profile' with deprecation alias (#594) | Leo Lapworth <leo@cuckoo.org> |
| 4 | `77bbe42a` | v0.41.0 | feat(cli): enhance prompts and denial diagnostics | Luke Hinds <lukehinds@gmail.com> |
| 5 | `87758af1` | v0.41.0 | fix(cli): improve profile save resilience and policy suggestions | Luke Hinds <lukehinds@gmail.com> |
| 6 | `073620e9` | v0.41.0 | chore: release v0.41.0 | Luke Hinds <lukehinds@gmail.com> |

**D-19 trailer block (verbatim, paste per commit):**

```
Upstream-commit: {sha_abbrev_8char}
Upstream-tag: v0.41.0
Upstream-author: {author_name} <{author_email}>
Co-Authored-By: {author_name} <{author_email}>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

**Coordination note:** This plan touches `cli.rs` — Wave 1 plans 34-03 (C5 keyring) and 34-06 (C9 trust scan) also touch `cli.rs`/`policy.rs`. Same-wave plans MUST have zero `files_modified` overlap; check the wave-1 plans before starting. If overlap exists, this plan serializes ahead in chronological order (C2 v0.41 < C5 v0.43 < C9 v0.49) — Plan 34-01 runs first, then Plan 34-03, then Plan 34-06.

**D-02 fallback gate:** If `git cherry-pick <sha>` produces conflict markers > 50 lines OR > 2 files, apply D-20 manual replay.

**D-34-E1 per-commit invariant:** `git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows'` must return zero hits per commit.

**Fork-divergence catalog cross-checks:**
- `nono policy` deprecation alias must NOT remove fork-only policy-related flags (verify against `cli.rs` for any `#[cfg(target_os = "windows")]`-gated arms in `Commands::Policy`).
- Phase 22-02 POLY-01-stricter posture (CONTRADICTION-A) must survive any policy-related changes — verify `cargo test -p nono-cli policy::tests::` POLY-01 sentinel passes after each commit.
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Pre-flight — fetch upstream + capture pre-Plan-34-01 HEAD + verify Plan 34-04 closed</name>
  <files>(git operations only)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-A2 (wave structure)
    - .planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md § Cluster: Profile/policy CLI consolidation + denial diagnostics
  </read_first>
  <action>
    1. Verify Plan 34-04 (Wave 0 gate) closed:
       ```
       git log --format='%B' --grep='Upstream-tag: v0.4[67]' main | grep -c '^Upstream-commit: '
       # Expected: ≥ 23 (the C7 cluster from Plan 34-04). If < 23, Plan 34-04 has not closed; STOP.
       ```

    2. Fetch upstream:
       ```
       git fetch upstream --tags
       ```

    3. Verify all 6 C2 SHAs reachable:
       ```
       for sha in 034be70 37488ce 5ff9bc3 77bbe42 87758af 073620e; do
         git cat-file -e $sha^{commit} || echo "MISSING: $sha"
       done
       ```

    4. Capture pre-Plan-34-01 HEAD:
       ```
       git log -1 --format='%H'   # Record in SUMMARY
       ```

    5. Baseline build:
       ```
       cargo build --workspace
       ```
  </action>
  <verify>
    <automated>git fetch upstream --tags &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - Plan 34-04 closed (≥ 23 v0.46/v0.47 commits on main).
    - All 6 C2 SHAs reachable.
    - `cargo build --workspace` exits 0.
    - SUMMARY records pre-Plan-34-01 HEAD SHA.
  </acceptance_criteria>
  <done>
    Ready to cherry-pick C2 cluster.
  </done>
</task>

<task type="auto">
  <name>Task 2: Cherry-pick all 6 C2 commits in chronological order with D-19 trailers</name>
  <files>
    crates/nono-cli/src/cli.rs
    crates/nono-cli/src/profile/mod.rs
    crates/nono-cli/src/policy.rs
    crates/nono-cli/src/main.rs
  </files>
  <read_first>
    - crates/nono-cli/src/cli.rs § `Commands` enum (current `Policy` + `Profile` variants if any)
    - crates/nono-cli/src/profile/mod.rs § `save` method (target of `87758af1` resilience fix)
    - crates/nono-cli/src/main.rs (target of `37488ce0` startup-prompt extraction)
    - `git show 034be703 37488ce0 5ff9bc33 77bbe42a 87758af1 073620e9 --stat` (all 6)
  </read_first>
  <action>
    For EACH of the 6 commits, follow this pattern:

    ```bash
    # Commit N/6: <sha> (<author>, "<subject>")
    git cherry-pick <sha>
    # D-02 gate: if conflicts > 50 lines OR > 2 files, apply D-20 manual replay
    cargo build --workspace
    git commit --amend -m "$(cat <<'EOF'
    <upstream subject verbatim>

    <upstream body if present>

    Upstream-commit: <8-char sha>
    Upstream-tag: v0.41.0
    Upstream-author: <author name> <<author email>>
    Co-Authored-By: <author name> <<author email>>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    **Specifics per commit:**

    1. `034be703` (Luke Hinds <lukehinds@gmail.com>, "feat(cli): improve denial diagnostics and profile saving workflow"): 12-file change. Touches `cli.rs`, `profile/mod.rs`, `policy.rs`, plus denial-diagnostic infrastructure. Read upstream's diff in full before cherry-pick. Verify POLY-01-stricter posture survives.

    2. `37488ce0` (Luke Hinds <lukehinds@gmail.com>, "refactor(cli-startup-prompt): extract startup prompt functions"): 3-file refactor. Moves startup-prompt logic into its own module.

    3. `5ff9bc33` (Leo Lapworth <leo@cuckoo.org>, "feat(cli): consolidate 'nono policy' subcommands under 'nono profile' with deprecation alias (#594)"): 7-file change. The key commit — adds `nono profile` subcommand tree + deprecation alias from `nono policy`. After cherry-pick, verify both `nono policy --help` AND `nono profile --help` work (deprecation alias forwards correctly).

    4. `77bbe42a` (Luke Hinds <lukehinds@gmail.com>, "feat(cli): enhance prompts and denial diagnostics"): 5-file change.

    5. `87758af1` (Luke Hinds <lukehinds@gmail.com>, "fix(cli): improve profile save resilience and policy suggestions"): 2-file change in `profile/mod.rs` + related.

    6. `073620e9` (Luke Hinds <lukehinds@gmail.com>, "chore: release v0.41.0"): Release bump.

    **After all 6:**

    ```bash
    git log --format='%B' HEAD~6..HEAD | grep -c '^Upstream-commit: '   # Expected: 6
    git log --format='%B' HEAD~6..HEAD | grep -c 'Upstream-Author:'     # Expected: 0
    git log --format='%B' HEAD~6..HEAD | grep -c '^Signed-off-by: '     # Expected: 12

    # Smoke: deprecation alias works
    cargo run --quiet --bin nono -- policy --help 2>&1 | head -5
    cargo run --quiet --bin nono -- profile --help 2>&1 | head -5
    ```
  </action>
  <verify>
    <automated>git log --format='%B' HEAD~6..HEAD | grep -c '^Upstream-commit: ' | grep -E '^6$' &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - 6 commits on `main` with verbatim D-19 trailers (lowercase 'a').
    - `git log --format=%B HEAD~6..HEAD | grep -c '^Upstream-commit: '` returns `6`.
    - `git log --format=%B HEAD~6..HEAD | grep -c 'Upstream-Author:'` returns `0`.
    - Per-commit D-34-E1 invariant returned 0.
    - `nono profile --help` exits 0; `nono policy --help` shows deprecation message and exits 0.
    - POLY-01 regression sentinel passes.
  </acceptance_criteria>
  <done>
    C2 cherry-pick chain complete.
  </done>
</task>

<task type="auto">
  <name>Task 3: D-34-D2 close-gate (8 gates)</name>
  <files>(read-only verification)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-D2
  </read_first>
  <action>
    Run all 8 gates in order:
    1. `cargo test --workspace --all-features` (Windows host).
    2. `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host).
    3. `cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used`.
    4. `cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used`.
    5. `cargo fmt --all -- --check`.
    6. Phase 15 5-row detached-console smoke gate.
    7. `cargo test -p nono-cli --test wfp_port_integration -- --ignored` (or documented-skip).
    8. `cargo test -p nono-cli --test learn_windows_integration` (or documented-skip).

    D-34-E1 invariant across the 6-commit chain:
    ```
    git log --format='%H' HEAD~6..HEAD | while read sha; do
      git diff --stat $sha^..$sha -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l
    done | sort -u
    # Expected: only "0" appears
    ```
  </action>
  <verify>
    <automated>cargo test --workspace --all-features &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo fmt --all -- --check</automated>
  </verify>
  <acceptance_criteria>
    - All 8 close-gates pass (or documented-skip for Gates 6-8 with rationale).
    - D-34-E1 invariant: 0 hits across all 6 commits.
  </acceptance_criteria>
  <done>
    Plan 34-01 close-gate cleared.
  </done>
</task>

<task type="auto">
  <name>Task 4: D-34-D1 plan-close push + PR</name>
  <files>(git push only)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-D1
  </read_first>
  <action>
    1. `git fetch origin && git log main..origin/main --oneline | wc -l` — expect 0.
    2. `git push origin main`.
    3. `git fetch origin && git log origin/main..main --oneline | wc -l` — expect 0.
    4. `gh pr create --title "Plan 34-01 (C2): CLI consolidation — nono policy → nono profile (v0.41.0, 6 commits)" --body "..."` with the 8-gate checklist.
  </action>
  <verify>
    <automated>git fetch origin &amp;&amp; test "$(git log origin/main..main --oneline | wc -l)" = "0"</automated>
  </verify>
  <acceptance_criteria>
    - `git log origin/main..main --oneline | wc -l` returns `0` post-push.
    - PR URL in SUMMARY.
  </acceptance_criteria>
  <done>
    Plan 34-01 published to origin.
  </done>
</task>

</tasks>

<non_goals>
**No Windows-only file touched (D-34-E1).**

**No fork-only retrofit beyond CLI surface alignment.** `nono profile` is absorbed AS-IS. No Windows-specific subcommand additions.

**No POLY-01 regression.** Fork's POLY-01-stricter posture survives per Phase 22 PATTERNS CONTRADICTION-A.

**No `nono policy` deletion.** Deprecation alias preserved for one release; users on `nono policy` continue to function.
</non_goals>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| User CLI invocation → clap parser | The `nono profile` deprecation alias must route correctly without exposing internal command structure. |
| Profile save → filesystem write | `87758af1` resilience fix changes profile-save behavior; must not introduce path-traversal regression. |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation |
|-----------|----------|-----------|----------|-------------|------------|
| T-34-01-01 | Tampering | D-21 Windows-only files invariant violation | **high** | mitigate (BLOCKING) | Per-commit D-34-E1 invariant check. |
| T-34-01-02 | Repudiation | D-19 trailer block missing or tampered | **high** | mitigate (BLOCKING) | Task 2 plan-close smoke check: 6 trailers, 12 sign-offs, 0 uppercase 'Author'. |
| T-34-01-03 | Tampering | `validate_path_within` removed by profile-save fix (`87758af1`) | medium | mitigate | Per-commit `grep -c 'validate_path_within'` count must not decrease. |
| T-34-01-04 | Elevation of Privilege | POLY-01-stricter regression via `nono policy` rename | medium | mitigate | POLY-01 regression sentinel test runs after each commit. |
| T-34-01-05 | Information Disclosure | Denial diagnostic exposes sensitive path (e.g., HOME) in error output | low | accept | Upstream's denial-diagnostic improvements (`034be703`, `77bbe42a`) are reviewed-public; standard nono error-output redaction applies. |
| T-34-01-06 | Denial of Service | Deprecation alias confuses clap parser (subcommand collision) | low | mitigate | Task 2 smoke: `nono policy --help` and `nono profile --help` both exit 0. |
</threat_model>

<verification>
- All 8 D-34-D2 close-gates pass.
- `git log --format='%B' HEAD~6..HEAD | grep -c '^Upstream-commit: '` returns `6`.
- `git log --format='%B' HEAD~6..HEAD | grep -c 'Upstream-Author:'` returns `0`.
- `git log --format='%B' HEAD~6..HEAD | grep -c '^Signed-off-by: '` returns `12`.
- Per-commit D-34-E1 invariant: 0 hits across all 6 commits.
- `nono profile --help` + `nono policy --help` (deprecation) both exit 0.
- `git log origin/main..main --oneline | wc -l` returns `0` post-push.
</verification>

<success_criteria>
- 6 atomic commits on `main` (cluster C2), each with D-19 trailer.
- `nono profile` becomes canonical; `nono policy` deprecation alias forwards.
- Enhanced denial diagnostics + profile-save resilience landed.
- All 8 D-34-D2 gates green.
- Zero Windows-only file edits.
- `origin/main` advanced; PR opened.
</success_criteria>

<output>
After completion, create `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-01-SUMMARY.md` with: Outcome, What was done (4 tasks), Verification (8 gates), Files changed, Commits (6-row table), Status, Deferred (any D-20 manual replays).
</output>
