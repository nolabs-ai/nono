---
phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
plan_number: 34-04
plan: 04
slug: path-canon-schema
cluster_id: C7
type: execute
wave: 0
depends_on: ["34-00"]
blocks: ["34-01", "34-02", "34-03", "34-05", "34-06", "34-07", "34-08", "34-09", "34-10"]
files_modified:
  - crates/nono-cli/src/profile/mod.rs
  - crates/nono-cli/src/policy.rs
  - crates/nono-cli/src/diagnostic.rs
  - crates/nono-cli/src/setup.rs
  - crates/nono-cli/src/capability_ext.rs
  - crates/nono-cli/Cargo.toml
  - crates/nono/src/capability.rs
  - Cargo.lock
upstream_tag_range: v0.46.0..v0.47.1
upstream_commit_count: 23
autonomous: true
requirements: [C7]
tags: [upst3, c7, path-canon, json-schema, wave-0, gate]

must_haves:
  truths:
    - "All 23 cluster-C7 upstream commits cherry-picked onto `main` in upstream chronological order"
    - "Every Plan 34-04 commit body carries the verbatim D-19 6-line trailer block (lowercase 'a' in Upstream-author:)"
    - "Smoke check: `git log --format='%B' HEAD~23..HEAD | grep -c '^Upstream-commit: '` equals 23 at plan close"
    - "D-34-E1 invariant: per-commit `git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows'` returns ZERO hits for every commit in the chain"
    - "Canonical JSON profile schema (upstream `f0abd41` `feat(profile): #594 phase 2 — canonical JSON schema restructure`) landed in `crates/nono-cli/src/profile/mod.rs` AND companion regeneration touch on the embedded schema (Plan 22-PATTERNS exact-analog: `Profile`/`ProfileDeserialize` companion-struct pattern)"
    - "`validate_path_within` (fork defense-in-depth, Phase 22-03 PKG-04 retention) is preserved at every call site in `crates/nono-cli/src/policy.rs` AND `crates/nono-cli/src/package_cmd.rs`; upstream's new `try_canonicalize` helper composes AS DEFENSE-IN-DEPTH, not as a replacement"
    - "Deny-overlap re-validation (`e2d0054 fix(cli): re-validate deny overlaps after all grants`) landed; the fork's `policy.rs::never_grant` defense (v2.1 Phase 19) composes with upstream's new re-validation pattern without weakening (verified via cargo test)"
    - "Path canonicalization unifies via the shared `try_canonicalize` helper (`69c55f4`, `bb3f512`, `be384ee`, `ee70922`, `dbc10da`); fork's Windows long-path handling via `dunce` continues to function (PATTERNS exact-analog: existing `dunce::simplified` call sites)"
    - "`jsonschema` crate version bump from 0.45.1 to 0.46.4 lands as a clean Cargo.lock change (`7329ef7`); `cargo build --workspace` exits 0 post-bump"
    - "Upstream test fixtures for path-canonicalization regression (PATTERNS D-34-E4) ported alongside production code; `cargo test -p nono-cli profile::tests::` exits 0"
    - "All 8 D-34-D2 close-gates pass on the Windows host"
    - "Plan 34-04 commits pushed to origin/main; `git log origin/main..main --oneline | wc -l` returns 0 at plan close"
  artifacts:
    - path: "crates/nono-cli/src/profile/mod.rs"
      provides: "Canonical JSON schema (post-`f0abd41`); extends/drafts resolution against sibling profiles (`bc44392`); serde-rendered values in show/diff JSON output (`f3e7f88`); skip self-references in sibling extends (`e4e73e1` — actually in C8, NOT C7; verify against ledger)"
      grep_pattern: "ProfileDeserialize|canonical_json_schema|deserialize_extends"
      min_call_sites: 5
    - path: "crates/nono-cli/src/policy.rs"
      provides: "Deny-overlap re-validation (`e2d0054`); `validate_path_within` defense-in-depth UNCHANGED"
      grep_pattern: "validate_path_within|re_validate|deny_overlap"
      grep_negative: "// removed validate_path_within"
    - path: "crates/nono-cli/src/diagnostic.rs"
      provides: "Migrated to shared `try_canonicalize` helper (`69c55f4`); extra blank line removed (`3f11772`)"
      grep_pattern: "try_canonicalize"
    - path: "crates/nono/src/capability.rs"
      provides: "Platform-specific dedup key (original on macOS, resolved on Linux) — `dbc10da`. Windows behavior preserved (fork's Windows path semantics survive)."
      grep_pattern: "dedup|cfg.*target_os"
    - path: "crates/nono-cli/Cargo.toml + Cargo.lock"
      provides: "jsonschema 0.45.1 → 0.46.4 bump (`7329ef7`)"
      grep_pattern: "jsonschema.*=.*\"0\\.46"
  key_links:
    - from: "ROADMAP § Phase 34 goal (canonical schema state is the foundation for downstream plans)"
      to: "Plan 34-04 cherry-pick chain"
      via: "23 atomic commits in chronological order, each with D-19 trailer"
      pattern: "Upstream-commit: (1f47b3c|96bd783|d49585b|e2d0054|efbfa49|167b4ea|1c89346|20e2286|26e80ed|3f11772|69c55f4|7a01e32|bb3f512|bc44392|be384ee|dbc10da|ee70922|f0abd41|f3e7f88|0cba04a|7329ef7|829c341|ab74f5c)"
    - from: "Fork's `validate_path_within` defense-in-depth (Phase 22-03 PKG-04 + Phase 26 PKGS-02)"
      to: "Upstream's new `try_canonicalize` helper (`69c55f4`, `bb3f512`)"
      via: "compose as DEFENSE-IN-DEPTH, not replacement; keep `validate_path_within` call sites"
      pattern: "validate_path_within"
    - from: "Fork's `policy.rs::never_grant` (v2.1 Phase 19)"
      to: "Upstream's deny-overlap re-validation (`e2d0054`)"
      via: "compose without weakening; both fire after all grants resolved"
      pattern: "never_grant|re_validate_deny"
    - from: "Plan 34-04 close (Wave 0 gate)"
      to: "Plans 34-01, 34-03, 34-06 (Wave 1) + 34-02, 34-05, 34-07, 34-08 (Wave 2) + 34-09, 34-10 (Wave 3)"
      via: "post-C7 canonical JSON schema state is the foundation downstream plans rebase against"
      pattern: "depends_on.*34-04"
---

<objective>
Land cluster C7 (upstream v0.46.0..v0.47.1, 23 commits) — the largest cluster in Phase 34 — onto `main` via per-commit cherry-pick in upstream chronological order, each with the D-19 trailer block. C7 is the **Wave 0 sequential gate** for Phase 34 (D-34-A2): every other will-sync plan's profile-touching changes rebase on top of the post-C7 canonical JSON schema state.

Three security-relevant items lead the cluster:
1. **Deny-overlap re-validation** (`e2d0054`) — closes an order-of-operations hole; the fork's `policy.rs::never_grant` (v2.1 Phase 19) is the Windows-side analog and composes with the upstream re-validation pattern without weakening.
2. **Unified path canonicalization with ancestor-walk fallback** (`bb3f512`, `69c55f4`, `dbc10da`, `ee70922`, `be384ee`) — directly relevant to fork's Windows long-path / UNC handling. Fork already canonicalizes via `dunce` on Windows; the new fallback shape composes AS DEFENSE-IN-DEPTH.
3. **Canonical JSON schema restructure** (`f0abd41`) — fork's schema regenerator must track upstream's canonical form for the Phase 24 drift-tool `profile` category to remain meaningful.

`829c341` (draft commands) + extends/drafts fixes (`bc44392`, `f3e7f88`) + jsonschema 0.46.4 bump (`7329ef7`) round out a coherent profile-tooling release-pair.

Purpose: A Windows user runs `nono profile show <profile>` / `nono profile diff` after Plan 34-04 lands and sees JSON output rendered through upstream's canonical-schema pipeline, with no regression in fork's Windows long-path handling, with `validate_path_within` still firing as defense-in-depth on every artifact-write callsite, and with deny-overlap re-validation firing as a fresh second-pass check after all grants resolve.

Output: 23 atomic commits on `main`, each carrying the D-19 6-line trailer block. Files in `crates/nono-cli/src/{profile/mod.rs,policy.rs,diagnostic.rs,setup.rs,capability_ext.rs}` and `crates/nono/src/capability.rs` evolved to upstream's v0.47.1 canonical shape. `Cargo.toml + Cargo.lock` carry the `jsonschema 0.46.4` bump. Zero edits to `*_windows.rs` files (D-34-E1). All 8 D-34-D2 close-gates green.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@CLAUDE.md
@.planning/STATE.md
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md
@.planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md
@.planning/phases/22-upst2-upstream-v038-v040-parity-sync/22-PATTERNS.md
@.planning/templates/upstream-sync-quick.md
@crates/nono-cli/src/profile/mod.rs
@crates/nono-cli/src/policy.rs
@crates/nono-cli/src/diagnostic.rs
@crates/nono/src/capability.rs

<interfaces>
**Cluster C7 cherry-pick chain (23 commits, upstream chronological order per DIVERGENCE-LEDGER.md):**

| Order | SHA | Tag | Subject | Upstream Author | Notes |
|-------|-----|-----|---------|-----------------|-------|
| 1 | `1f47b3c8` | v0.46.0 | fix: Update examples in setup.rs | Rob Zinkov <zaxtax@users.noreply.github.com> | docs/examples touch |
| 2 | `96bd7838` | v0.46.0 | test: exclude system_write_linux in post-CWD overlap regression test | Luke Hinds <luke@alwaysfurther.ai> | Linux-only test gating |
| 3 | `d49585b8` | v0.46.0 | chore: release v0.46.0 | Luke Hinds <lukehinds@gmail.com> | release bump |
| 4 | `e2d00546` | v0.46.0 | fix(cli): re-validate deny overlaps after all grants | Luke Hinds <lukehinds@gmail.com> | **security item #1** — compose with fork `policy.rs::never_grant` |
| 5 | `efbfa49b` | v0.46.0 | feat(network): support GitLab developer domains | Erran Carey <ecarey@gitlab.com> | new domain entry |
| 6 | `167b4ea0` | v0.47.0 | fix: doc changes + relax strict cap check | SequeI <asiek@redhat.com> | doc + cap-check loosening; verify fork posture |
| 7 | `1c893465` | v0.47.0 | style: run cargo fmt | Advaith Sujith <advaithsujith6@outlook.com> | fmt drift |
| 8 | `20e2286d` | v0.47.0 | Add macOS warning when --allow targets a deny-group path | SequeI <asiek@redhat.com> | macOS Seatbelt-specific warning |
| 9 | `26e80ed5` | v0.47.0 | fix: replace unwrap() with expect() in path tests for clippy | Advaith Sujith <advaith@alwaysfurther.ai> | clippy hygiene |
| 10 | `3f117725` | v0.47.0 | style: remove extra blank line in diagnostic.rs | Advaith Sujith <advaith@alwaysfurther.ai> | fmt drift |
| 11 | `69c55f4f` | v0.47.0 | fix: migrate diagnostic.rs to shared try_canonicalize helper | Advaith Sujith <advaith@alwaysfurther.ai> | **security item #2** — path canon unification |
| 12 | `7a01e32a` | v0.47.0 | chore: release v0.47.0 | Luke Hinds <lukehinds@gmail.com> | release bump |
| 13 | `bb3f512d` | v0.47.0 | fix: unify path canonicalization with ancestor-walk fallback | Advaith Sujith <advaithsujith6@outlook.com> | **security item #2** — core canonicalization unification |
| 14 | `bc443928` | v0.47.0 | fix: resolve extends against sibling profiles in the same directory | SequeI <asiek@redhat.com> | extends resolution fix |
| 15 | `be384ee4` | v0.47.0 | perf: eliminate redundant canonicalize syscalls per review feedback | Advaith Sujith <advaithsujith6@outlook.com> | perf follow-up to bb3f512d |
| 16 | `dbc10da8` | v0.47.0 | fix(capability): platform-specific dedup key (original on macOS, resolved on Linux) | Mark Sisson <5761292+marksisson@users.noreply.github.com> | **Windows-relevant** — verify fork's Windows dedup behavior preserved |
| 17 | `ee70922d` | v0.47.0 | fix: canonicalize protected roots at call sites to handle raw paths | Advaith Sujith <advaith@alwaysfurther.ai> | **security item #2** — protected-root canon at call sites |
| 18 | `f0abd413` | v0.47.0 | feat(profile): #594 phase 2 — canonical JSON schema restructure (#594) | Leo Lapworth <leo@cuckoo.org> | **security item #3** — canonical JSON schema; 23-file diff |
| 19 | `f3e7f885` | v0.47.0 | fix(profile): emit serde-rendered values in show/diff JSON output | Matt Palcic <matt.palcic@naturalforms.com> | show/diff JSON output fix |
| 20 | `0cba04a5` | v0.47.1 | chore: release v0.47.1 | Luke Hinds <lukehinds@gmail.com> | release bump |
| 21 | `7329ef73` | v0.47.1 | chore(deps): bump jsonschema from 0.45.1 to 0.46.4 | dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com> | dep bump; Cargo.lock |
| 22 | `829c341a` | v0.47.1 | add commands to manage profile drafts and check package status | Luke Hinds <lukehinds@gmail.com> | profile drafts subcommand |
| 23 | `ab74f5cd` | v0.47.1 | docs: fix stale references, deprecation wording, and built-in vs pack distinction | SequeI <asiek@redhat.com> | docs touch |

**D-19 trailer block (verbatim, paste into every commit's amended body):**

```
Upstream-commit: {sha_abbrev_8char}
Upstream-tag: {upstream_tag}
Upstream-author: {author_name} <{author_email}>
Co-Authored-By: {author_name} <{author_email}>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

Field rules (per `.planning/templates/upstream-sync-quick.md` § D-19 cherry-pick trailer block):
- Lowercase 'a' in `Upstream-author:` (NOT `Upstream-Author:`).
- 8-character SHA abbrev in `Upstream-commit:`.
- `Upstream-author:` and `Co-Authored-By:` carry the SAME `name <email>`.
- Two `Signed-off-by:` lines (DCO + GitHub attribution).
- Trailer block separated from commit-message body by EXACTLY ONE blank line.

**D-02 fallback gate (per Phase 22 D-02):** If `git cherry-pick <sha>` produces conflict markers exceeding 50 lines OR spanning >2 forked files OR the semantic meaning is ambiguous against fork's current `profile/mod.rs` (already heavily forked: +732/-414 vs upstream v0.40.1 baseline), `git cherry-pick --abort` and apply D-20 manual-port (commit body documents the manual replay with `Upstream-commit: <sha> (replayed manually)`).

**D-34-E1 per-commit invariant verification (run after EVERY cherry-pick + amend, before moving to the next commit):**

```bash
git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows'
# Expected: ZERO output. If output exists, abort:
#   git reset --soft HEAD~1
#   git restore --staged crates/**/*_windows.rs crates/nono-cli/src/exec_strategy_windows/
#   git checkout HEAD -- crates/**/*_windows.rs crates/nono-cli/src/exec_strategy_windows/
#   git commit (re-amend the trailer)
# Then re-run the invariant check.
```

**Fork-divergence catalog cross-checks (read `.planning/templates/upstream-sync-quick.md` § Fork-divergence catalog before resolving any conflict):**

1. **`validate_path_within` defense-in-depth retention** (Phase 22-03 PKG-04 + Phase 26 PKGS-02). Cluster C7 introduces upstream's new `try_canonicalize` helper. Fork's `validate_path_within` MUST be preserved at every call site. Search for upstream commits that REMOVE `validate_path_within` calls — KEEP them in the fork with the comment: `// Defense-in-depth (fork divergence: see Phase 22-03 PKG-04 + Phase 26 PKGS-02). Do not remove without security review.`

2. **Deferred enum variants** — Phase 26 PKGS-02 added `ArtifactType::Plugin` as the 7th variant. C7 cluster's profile-touching commits (`f0abd41` canonical JSON schema restructure) may serialize `ArtifactType` values. Verify round-trip parity for the Plugin variant after `f0abd41` lands.

3. **Async-runtime wrapping for `load_production_trusted_root`** — N/A for C7 (this catalog entry applies to Phase 32 TUF work; C7 does not touch the trust subsystem).

4. **Hooks subsystem ownership** — N/A for C7 (this catalog entry applies to C6 pack migration, covered by Plan 34-09 manual replay).

5. **D-21 Windows-only file globs** — enforced per-commit by the D-34-E1 invariant check above. Zero edits to `*_windows.rs` or `crates/nono-cli/src/exec_strategy_windows/` in any of the 23 commits.

**Per-commit commit body template** (after `git cherry-pick <sha>` + conflict resolution + `cargo build --workspace`):

```bash
git commit --amend -m "$(cat <<'EOF'
<original upstream subject — copy verbatim from `git log -1 <sha> --format='%s'`>

<original upstream body if present — copy verbatim from `git log -1 <sha> --format='%b'`>

Upstream-commit: <8-char sha>
Upstream-tag: <v0.46.0 | v0.47.0 | v0.47.1 — pick from the table above>
Upstream-author: <author name> <<author email>>
Co-Authored-By: <author name> <<author email>>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
EOF
)"
```

**Pattern map analogs (PATTERNS.md § Profile struct field additions):**

- Profile struct field additions follow existing `Profile` + `ProfileDeserialize` companion pattern with `#[serde(default)]` on every field — new fields slot in identically (PATTERNS § 1).
- Path canonicalization fork side: `dunce::simplified` is the existing Windows long-path normalizer. Upstream's new `try_canonicalize` helper composes — both can fire (upstream's at policy/diagnostic call sites; fork's `dunce` at Windows-specific call sites).
- Deny-overlap re-validation: fork's `policy.rs::apply_deny_overrides` (PATTERNS § POLY-01) already implements rejection at line ~774. Upstream's new re-validation pattern (`e2d0054`) fires AFTER all grants resolve — compose as second-pass.
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Pre-flight — fetch upstream, verify cluster boundaries, capture pre-Plan-34-04 HEAD</name>
  <files>(no files modified — git operations only)</files>
  <read_first>
    - .planning/phases/33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md § Cluster: Path canonicalization + profile JSON schema restructure (introduced in v0.46.0) (lines 149-180; 23-commit table)
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-A2 (Wave 0 gate posture) + § D-34-E1..E5 (invariants)
  </read_first>
  <action>
    1. Fetch upstream + tags:
       ```
       git fetch upstream --tags
       ```

    2. Confirm cluster boundaries hold against live upstream HEAD (`make check-upstream-drift` re-validation — D-34 reproducibility):
       ```
       make check-upstream-drift ARGS="--from v0.40.1 --to v0.52.0 --format json" > /tmp/c7-revalidate.json 2>&1 || \
         bash scripts/check-upstream-drift.sh --from v0.40.1 --to v0.52.0 --format json > /tmp/c7-revalidate.json
       # If upstream HEAD has advanced past 54f7c32a (Phase 33 audit-time HEAD), the C7 commit list MAY have changed.
       # Diff the commit set: the 23 shas listed in the cluster table should ALL appear in the re-validated JSON output.
       for sha in 1f47b3c 96bd783 d49585b e2d0054 efbfa49 167b4ea 1c89346 20e2286 26e80ed 3f11772 \
                  69c55f4 7a01e32 bb3f512 bc44392 be384ee dbc10da ee70922 f0abd41 f3e7f88 0cba04a \
                  7329ef7 829c341 ab74f5c; do
         grep -c "$sha" /tmp/c7-revalidate.json || echo "MISSING: $sha"
       done
       ```
       If any SHA is missing OR if new commits appear in the v0.46.0..v0.47.1 range that are NOT in the cluster table, STOP and document in SUMMARY. Phase 33 ledger boundaries are authoritative; new commits NOT covered by Phase 33 audit are out of scope for Plan 34-04.

    3. Capture pre-Plan-34-04 HEAD SHA for traceability:
       ```
       git log -1 --format='%H %s' main
       # Record this SHA in SUMMARY § "Pre-Plan-34-04 HEAD"
       ```

    4. Verify `main` is clean:
       ```
       git status
       # Expected: working tree clean
       ```

    5. Confirm `cargo build --workspace` is green BEFORE starting (establishes baseline for the per-commit gate):
       ```
       cargo build --workspace
       # Expected: exit 0
       ```
  </action>
  <verify>
    <automated>git fetch upstream --tags &amp;&amp; git status --porcelain | wc -l | grep -E '^0$' &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - `git fetch upstream` exits 0; tags v0.46.0, v0.47.0, v0.47.1 reachable (`git tag --list 'v0.4*' | grep -c 'v0\.4[67]'` returns at least 3).
    - All 23 cluster-C7 SHAs are reachable on the upstream remote (`for sha in ...; do git cat-file -e $sha^{commit} || echo MISSING; done` returns zero MISSING entries).
    - `git status` reports working tree clean.
    - `cargo build --workspace` exits 0 (baseline green; per-commit gate's reference point).
    - SUMMARY records the pre-Plan-34-04 HEAD SHA.
  </acceptance_criteria>
  <done>
    Plan 34-04 cherry-pick chain ready to begin.
  </done>
</task>

<task type="auto">
  <name>Task 2: Cherry-pick commits 1-5 (v0.46.0 cluster — setup.rs + test exclude + release + deny-overlap re-validation + GitLab domain)</name>
  <files>
    crates/nono-cli/src/setup.rs
    crates/nono-cli/src/policy.rs
    crates/nono-cli/src/profile/mod.rs
    (and others as cherry-picks reveal)
  </files>
  <read_first>
    - crates/nono-cli/src/setup.rs (read current shape to anticipate `1f47b3c` examples diff)
    - crates/nono-cli/src/policy.rs (read current `apply_deny_overrides` shape — the analog for `e2d00546`'s re-validation pattern; PATTERNS § POLY-01)
    - `git show 1f47b3c8 96bd7838 d49585b8 e2d00546 efbfa49b --stat` (anticipate conflict surface)
    - `git log -1 1f47b3c8 --format='%B'` ... through all 5 (capture upstream commit bodies for the D-19 amend step)
    - .planning/templates/upstream-sync-quick.md § Fork-divergence catalog § `validate_path_within` defense-in-depth retention (read in full; `e2d00546` is the deny-overlap commit that may interact with fork's `never_grant`)
  </read_first>
  <action>
    Cherry-pick each commit individually (D-19 atomicity); after EACH commit, run the D-34-E1 invariant check + a per-commit build:

    **Commit 1/23: `1f47b3c8` (v0.46.0, Rob Zinkov, "fix: Update examples in setup.rs"):**

    ```bash
    git cherry-pick 1f47b3c8
    # D-02 gate: if conflicts > 50 lines OR > 2 files, abort + manual replay
    # Resolve in place if conflicts are small (this commit is examples-only; conflicts unlikely)
    cargo build --workspace
    git commit --amend -m "$(cat <<'EOF'
    fix: Update examples in setup.rs

    Upstream-commit: 1f47b3c8
    Upstream-tag: v0.46.0
    Upstream-author: Rob Zinkov <zaxtax@users.noreply.github.com>
    Co-Authored-By: Rob Zinkov <zaxtax@users.noreply.github.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    # D-34-E1 invariant verify:
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l
    # Expected: 0
    ```

    **Commit 2/23: `96bd7838` (v0.46.0, Luke Hinds, "test: exclude system_write_linux in post-CWD overlap regression test"):**

    Same shape. The `Upstream-author:` and `Co-Authored-By:` lines use `Luke Hinds <luke@alwaysfurther.ai>` (NOT `lukehinds@gmail.com` — this commit was authored with the @alwaysfurther.ai email; verify via `git log -1 96bd7838 --format='%an <%ae>'`).

    ```bash
    git cherry-pick 96bd7838
    cargo build --workspace
    git commit --amend -m "$(cat <<'EOF'
    test: exclude system_write_linux in post-CWD overlap regression test

    Upstream-commit: 96bd7838
    Upstream-tag: v0.46.0
    Upstream-author: Luke Hinds <luke@alwaysfurther.ai>
    Co-Authored-By: Luke Hinds <luke@alwaysfurther.ai>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    **Commit 3/23: `d49585b8` (v0.46.0, Luke Hinds, "chore: release v0.46.0"):**

    Release-bump commit. May touch `Cargo.toml` version field. Use `Luke Hinds <lukehinds@gmail.com>` (this commit was authored under the gmail email; verify via `git log -1 d49585b8 --format='%an <%ae>'`).

    ```bash
    git cherry-pick d49585b8
    # If conflict with fork's Cargo.toml version: fork is on a DIFFERENT version stream (no upstream version field sync); keep fork's version, take upstream's other changes.
    cargo build --workspace
    git commit --amend -m "$(cat <<'EOF'
    chore: release v0.46.0

    Upstream-commit: d49585b8
    Upstream-tag: v0.46.0
    Upstream-author: Luke Hinds <lukehinds@gmail.com>
    Co-Authored-By: Luke Hinds <lukehinds@gmail.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    **Commit 4/23: `e2d00546` (v0.46.0, Luke Hinds, "fix(cli): re-validate deny overlaps after all grants") — SECURITY ITEM #1:**

    Read upstream's patch carefully BEFORE cherry-pick:
    ```bash
    git show e2d00546
    ```

    Confirm the new re-validation pattern fires AFTER fork's `apply_deny_overrides`. If upstream's commit accidentally removes a fork-side `never_grant` call, KEEP the fork-side call (defense-in-depth) AND apply upstream's re-validation as a second-pass check.

    ```bash
    git cherry-pick e2d00546
    # Conflict resolution: preserve fork's `policy.rs::apply_deny_overrides` calls verbatim; layer upstream's re-validation AFTER (not instead of)
    cargo build --workspace
    cargo test -p nono-cli policy::tests::   # Verify fork's POLY-01 tests still pass
    git commit --amend -m "$(cat <<'EOF'
    fix(cli): re-validate deny overlaps after all grants

    Composes with fork's policy.rs::never_grant defense (v2.1 Phase 19): upstream's
    new re-validation fires AFTER all grants resolve, fork's never_grant fires at
    grant-time. Both layers retained for defense-in-depth.

    Upstream-commit: e2d00546
    Upstream-tag: v0.46.0
    Upstream-author: Luke Hinds <lukehinds@gmail.com>
    Co-Authored-By: Luke Hinds <lukehinds@gmail.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    grep -c 'never_grant\|apply_deny_overrides' crates/nono-cli/src/policy.rs   # Expected: same or higher than pre-commit count
    ```

    **Commit 5/23: `efbfa49b` (v0.46.0, Erran Carey, "feat(network): support GitLab developer domains"):**

    ```bash
    git cherry-pick efbfa49b
    cargo build --workspace
    git commit --amend -m "$(cat <<'EOF'
    feat(network): support GitLab developer domains

    Upstream-commit: efbfa49b
    Upstream-tag: v0.46.0
    Upstream-author: Erran Carey <ecarey@gitlab.com>
    Co-Authored-By: Erran Carey <ecarey@gitlab.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    After all 5 commits, run the per-task post-check:
    ```bash
    git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-commit: '   # Expected: 5
    git log --format='%B' HEAD~5..HEAD | grep -c '^Signed-off-by: '     # Expected: 10 (2 per commit)
    git log --format='%B' HEAD~5..HEAD | grep -c 'Upstream-author:'     # Expected: 5 (lowercase 'a' verified)
    git log --format='%B' HEAD~5..HEAD | grep -c 'Upstream-Author:'     # Expected: 0 (NO uppercase variant)
    cargo build --workspace
    ```
  </action>
  <verify>
    <automated>git log --format='%B' HEAD~5..HEAD | grep -c '^Upstream-commit: ' | grep -E '^5$' &amp;&amp; git log --format='%B' HEAD~5..HEAD | grep -c 'Upstream-Author:' | grep -E '^0$' &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - 5 commits landed on `main` (1f47b3c8, 96bd7838, d49585b8, e2d00546, efbfa49b) in chronological order.
    - Each commit body carries verbatim D-19 6-line trailer (lowercase 'a' in `Upstream-author:`).
    - `git log --format=%B HEAD~5..HEAD | grep -c '^Upstream-commit: '` returns `5`.
    - `git log --format=%B HEAD~5..HEAD | grep -c 'Upstream-Author:'` returns `0` (case-sensitivity invariant).
    - For each commit: `git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l` returned `0`.
    - `grep -c 'never_grant\|apply_deny_overrides' crates/nono-cli/src/policy.rs` returns the same or higher count than pre-Plan-34-04 baseline (fork defense-in-depth preserved).
    - `cargo build --workspace` exits 0 after each commit.
  </acceptance_criteria>
  <done>
    Commits 1-5 landed; deny-overlap re-validation composes with fork's never_grant; D-34-E1 invariant held every commit.
  </done>
</task>

<task type="auto">
  <name>Task 3: Cherry-pick commits 6-12 (v0.47.0 cluster-A — strict-cap relax + fmt + macOS warning + clippy + path canon helpers)</name>
  <files>
    crates/nono-cli/src/policy.rs
    crates/nono-cli/src/profile/mod.rs
    crates/nono-cli/src/diagnostic.rs
    crates/nono-cli/src/capability_ext.rs
  </files>
  <read_first>
    - crates/nono-cli/src/policy.rs § `validate_path_within` callsites (fork defense-in-depth — must survive)
    - crates/nono-cli/src/diagnostic.rs § canonicalization callsites (this is where `try_canonicalize` lands per `69c55f4f`)
    - crates/nono-cli/src/capability_ext.rs § dedup logic (this is where `dbc10da` platform-specific dedup key lands)
    - `git show 167b4ea0 1c893465 20e2286d 26e80ed5 3f117725 69c55f4f 7a01e32a --stat` (anticipate conflict surface for each)
    - .planning/templates/upstream-sync-quick.md § Fork-divergence catalog § `validate_path_within` defense-in-depth retention (read in full again — `69c55f4f`'s `try_canonicalize` migration may interact with fork's `validate_path_within` callsites; layer both, do not replace)
  </read_first>
  <action>
    **Commit 6/23: `167b4ea0` (v0.47.0, SequeI, "fix: doc changes + relax strict cap check"):**

    ⚠ The "relax strict cap check" wording is a yellow flag. Read upstream's patch carefully: if the relaxation weakens fork's POLY-01-stricter posture (PATTERNS CONTRADICTION-A), STOP and document in SUMMARY. Fork retained stricter POLY-01 in Phase 22; this commit MUST NOT regress that.

    ```bash
    git show 167b4ea0
    # Read the diff carefully. If it weakens a fork-side stricter check, do NOT apply that portion; keep fork's stricter posture and document in commit body.
    git cherry-pick 167b4ea0
    # Conflict resolution: preserve fork's POLY-01-stricter; if upstream's relax removes a fork-side check, KEEP fork's check with a defense-in-depth comment
    cargo build --workspace
    cargo test -p nono-cli policy::tests::   # POLY-01 regression sentinel
    git commit --amend -m "$(cat <<'EOF'
    fix: doc changes + relax strict cap check

    Upstream's cap-check relaxation applied to upstream-side strictness only;
    fork's POLY-01-stricter posture (Phase 22-02 PATTERNS CONTRADICTION-A)
    preserved verbatim.

    Upstream-commit: 167b4ea0
    Upstream-tag: v0.47.0
    Upstream-author: SequeI <asiek@redhat.com>
    Co-Authored-By: SequeI <asiek@redhat.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    **Commit 7/23: `1c893465` (v0.47.0, Advaith Sujith, "style: run cargo fmt"):**

    ```bash
    git cherry-pick 1c893465
    # Fmt-only; conflicts unlikely. If conflict: cargo fmt --all and substitute.
    cargo fmt --all -- --check
    git commit --amend -m "$(cat <<'EOF'
    style: run cargo fmt

    Upstream-commit: 1c893465
    Upstream-tag: v0.47.0
    Upstream-author: Advaith Sujith <advaithsujith6@outlook.com>
    Co-Authored-By: Advaith Sujith <advaithsujith6@outlook.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    **Commit 8/23: `20e2286d` (v0.47.0, SequeI, "Add macOS warning when --allow targets a deny-group path"):**

    macOS-only feature. The warning fires during `finalize_caps` on macOS; cross-platform code path remains valid; fork's Windows path doesn't trigger the warning (Windows doesn't have Seatbelt's silent-override quirk).

    ```bash
    git cherry-pick 20e2286d
    cargo build --workspace
    cargo build --workspace --target x86_64-apple-darwin   # Verify the macOS-gated warning code compiles for the macOS target (D-34-D2 gate 4 lesson)
    git commit --amend -m "$(cat <<'EOF'
    Add macOS warning when --allow targets a deny-group path

    On macOS, Seatbelt deny rules silently override earlier allow rules,
    so --allow on a path like ~/.gnupg has no effect when deny_credentials
    is active. Detect this overlap in finalize_caps and warn the user to
    use --override-deny.

    Upstream-commit: 20e2286d
    Upstream-tag: v0.47.0
    Upstream-author: SequeI <asiek@redhat.com>
    Co-Authored-By: SequeI <asiek@redhat.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    **Commit 9/23: `26e80ed5` (v0.47.0, Advaith Sujith, "fix: replace unwrap() with expect() in path tests for clippy"):**

    ⚠ The fork CLAUDE.md forbids `.unwrap()` AND prefers `Result` propagation over `.expect()` for non-test code. This commit's `unwrap → expect` substitution is in TEST code (per the subject); verify the diff stays in `#[cfg(test)]` modules.

    ```bash
    git show 26e80ed5
    # Verify the diff is in test modules only. If any production code is touched, restructure the change.
    git cherry-pick 26e80ed5
    cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used
    git commit --amend -m "$(cat <<'EOF'
    fix: replace unwrap() with expect() in path tests for clippy

    Test-module-only change. Fork's clippy::unwrap_used policy permits
    .expect() in test code; production code remains Result-propagating.

    Upstream-commit: 26e80ed5
    Upstream-tag: v0.47.0
    Upstream-author: Advaith Sujith <advaith@alwaysfurther.ai>
    Co-Authored-By: Advaith Sujith <advaith@alwaysfurther.ai>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    **Commit 10/23: `3f117725` (v0.47.0, Advaith Sujith, "style: remove extra blank line in diagnostic.rs"):**

    ```bash
    git cherry-pick 3f117725
    cargo fmt --all -- --check
    git commit --amend -m "$(cat <<'EOF'
    style: remove extra blank line in diagnostic.rs

    Upstream-commit: 3f117725
    Upstream-tag: v0.47.0
    Upstream-author: Advaith Sujith <advaith@alwaysfurther.ai>
    Co-Authored-By: Advaith Sujith <advaith@alwaysfurther.ai>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    **Commit 11/23: `69c55f4f` (v0.47.0, Advaith Sujith, "fix: migrate diagnostic.rs to shared try_canonicalize helper") — SECURITY ITEM #2 PART 1:**

    This introduces the `try_canonicalize` helper. Fork's `validate_path_within` calls in `policy.rs` and `package_cmd.rs` are NOT touched by this commit (`diagnostic.rs` only). Verify after cherry-pick that `validate_path_within` callsites are unchanged.

    ```bash
    git cherry-pick 69c55f4f
    cargo build --workspace
    grep -c 'try_canonicalize' crates/nono-cli/src/diagnostic.rs   # Expected: ≥ 1
    grep -c 'validate_path_within' crates/nono-cli/src/policy.rs crates/nono-cli/src/package_cmd.rs   # Expected: same as pre-commit count
    git commit --amend -m "$(cat <<'EOF'
    fix: migrate diagnostic.rs to shared try_canonicalize helper

    Upstream-commit: 69c55f4f
    Upstream-tag: v0.47.0
    Upstream-author: Advaith Sujith <advaith@alwaysfurther.ai>
    Co-Authored-By: Advaith Sujith <advaith@alwaysfurther.ai>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    **Commit 12/23: `7a01e32a` (v0.47.0, Luke Hinds, "chore: release v0.47.0"):**

    Release bump. May touch Cargo.toml version; preserve fork's version stream as in Commit 3.

    ```bash
    git cherry-pick 7a01e32a
    cargo build --workspace
    git commit --amend -m "$(cat <<'EOF'
    chore: release v0.47.0

    Upstream-commit: 7a01e32a
    Upstream-tag: v0.47.0
    Upstream-author: Luke Hinds <lukehinds@gmail.com>
    Co-Authored-By: Luke Hinds <lukehinds@gmail.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    Per-task post-check after all 7 commits (commits 6-12):
    ```bash
    git log --format='%B' HEAD~7..HEAD | grep -c '^Upstream-commit: '   # Expected: 7
    git log --format='%B' HEAD~7..HEAD | grep -c 'Upstream-Author:'     # Expected: 0
    cargo build --workspace
    cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used
    ```
  </action>
  <verify>
    <automated>git log --format='%B' HEAD~7..HEAD | grep -c '^Upstream-commit: ' | grep -E '^7$' &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used &amp;&amp; grep -c 'validate_path_within' crates/nono-cli/src/policy.rs</automated>
  </verify>
  <acceptance_criteria>
    - 7 commits landed (167b4ea0, 1c893465, 20e2286d, 26e80ed5, 3f117725, 69c55f4f, 7a01e32a) in chronological order.
    - Each commit body carries verbatim D-19 trailer (lowercase 'a').
    - `git log --format=%B HEAD~7..HEAD | grep -c '^Upstream-commit: '` returns `7`.
    - `grep -c 'try_canonicalize' crates/nono-cli/src/diagnostic.rs` returns ≥ 1.
    - `grep -c 'validate_path_within' crates/nono-cli/src/policy.rs` returns the same or higher count than pre-Plan-34-04 baseline.
    - Per-commit D-34-E1 invariant check returned 0 for each commit.
    - `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` exits 0.
  </acceptance_criteria>
  <done>
    Commits 6-12 landed; `try_canonicalize` introduced in diagnostic.rs; fork's `validate_path_within` preserved; POLY-01-stricter posture intact.
  </done>
</task>

<task type="auto">
  <name>Task 4: Cherry-pick commits 13-19 (v0.47.0 cluster-B — path canon unification + extends fix + capability dedup + canonical JSON schema)</name>
  <files>
    crates/nono-cli/src/profile/mod.rs
    crates/nono-cli/src/policy.rs
    crates/nono-cli/src/diagnostic.rs
    crates/nono/src/capability.rs
    (and others as cherry-picks reveal)
  </files>
  <read_first>
    - crates/nono-cli/src/profile/mod.rs (read the full Profile + ProfileDeserialize companion structs — `f0abd41` is a 23-file canonical-schema restructure with high conflict potential; PATTERNS § 1 analog)
    - crates/nono/src/capability.rs § dedup logic (where `dbc10da` lands; fork's Windows dedup behavior must be preserved — verify Windows arm is unchanged)
    - `git show bb3f512d --stat` and `git show f0abd413 --stat` (anticipate large diffs)
    - .planning/templates/upstream-sync-quick.md § Fork-divergence catalog § Deferred enum variants (round-trip parity for `ArtifactType::Plugin` after `f0abd41` lands)
  </read_first>
  <action>
    **Commit 13/23: `bb3f512d` (v0.47.0, Advaith Sujith, "fix: unify path canonicalization with ancestor-walk fallback") — SECURITY ITEM #2 PART 2:**

    Core canonicalization unification. Touches multiple files. Read upstream's diff first.

    ```bash
    git show bb3f512d --stat
    # Expected: 8 files changed per ledger
    git show bb3f512d -- crates/   # Read the production-code diff in full
    git cherry-pick bb3f512d
    # D-02 gate: 8-file diff is on the edge of the threshold. If conflicts span >2 files significantly, consider D-20 manual replay.
    cargo build --workspace
    cargo test -p nono-cli profile::tests::
    git commit --amend -m "$(cat <<'EOF'
    fix: unify path canonicalization with ancestor-walk fallback

    Fork's validate_path_within (Phase 22-03 PKG-04 + Phase 26 PKGS-02
    defense-in-depth) preserved at all callsites; ancestor-walk fallback
    composes with fork's dunce::simplified-based Windows long-path handling.

    Upstream-commit: bb3f512d
    Upstream-tag: v0.47.0
    Upstream-author: Advaith Sujith <advaithsujith6@outlook.com>
    Co-Authored-By: Advaith Sujith <advaithsujith6@outlook.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    grep -c 'validate_path_within' crates/nono-cli/src/policy.rs crates/nono-cli/src/package_cmd.rs   # Expected: same as pre-Plan-34-04 baseline
    ```

    **Commit 14/23: `bc443928` (v0.47.0, SequeI, "fix: resolve extends against sibling profiles in the same directory"):**

    ```bash
    git cherry-pick bc443928
    cargo build --workspace
    cargo test -p nono-cli profile::tests::extends   # Verify extends-resolution tests pass
    git commit --amend -m "$(cat <<'EOF'
    fix: resolve extends against sibling profiles in the same directory

    Upstream-commit: bc443928
    Upstream-tag: v0.47.0
    Upstream-author: SequeI <asiek@redhat.com>
    Co-Authored-By: SequeI <asiek@redhat.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    **Commit 15/23: `be384ee4` (v0.47.0, Advaith Sujith, "perf: eliminate redundant canonicalize syscalls per review feedback") — SECURITY ITEM #2 PART 3:**

    Performance follow-up to `bb3f512d`. Reduces redundant canonicalize calls. Verify fork's `validate_path_within` callsites are UNCHANGED (perf optimization should not collapse defense-in-depth checks).

    ```bash
    git cherry-pick be384ee4
    cargo build --workspace
    grep -c 'validate_path_within' crates/nono-cli/src/policy.rs crates/nono-cli/src/package_cmd.rs   # Expected: same as pre-Plan-34-04 baseline
    git commit --amend -m "$(cat <<'EOF'
    perf: eliminate redundant canonicalize syscalls per review feedback

    Fork's validate_path_within calls preserved — perf opt collapses
    redundant canonicalize calls, not defense-in-depth validation calls.

    Upstream-commit: be384ee4
    Upstream-tag: v0.47.0
    Upstream-author: Advaith Sujith <advaithsujith6@outlook.com>
    Co-Authored-By: Advaith Sujith <advaithsujith6@outlook.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    **Commit 16/23: `dbc10da8` (v0.47.0, Mark Sisson, "fix(capability): platform-specific dedup key (original on macOS, resolved on Linux)") — Windows-relevant:**

    This commit introduces platform-specific dedup behavior. Verify Windows behavior is either preserved as-is OR explicitly handled (no Windows code path should regress).

    ```bash
    git show dbc10da8 -- crates/nono/src/capability.rs
    # Read carefully: the dedup key on macOS uses original path, on Linux uses resolved. Windows behavior must be preserved.
    git cherry-pick dbc10da8
    # If upstream's diff puts the platform-specific dispatch behind cfg(target_os = "macos") | cfg(target_os = "linux") and leaves Windows uncovered, ADD a Windows arm that matches fork's current behavior (likely "original on Windows" since fork uses dunce for canonicalization elsewhere — verify against current code).
    cargo build --workspace
    cargo test -p nono capability::   # Verify capability dedup tests pass
    git commit --amend -m "$(cat <<'EOF'
    fix(capability): platform-specific dedup key (original on macOS, resolved on Linux)

    Windows arm preserved per fork's current dunce-based canonicalization
    behavior; no Windows code path regression.

    Upstream-commit: dbc10da8
    Upstream-tag: v0.47.0
    Upstream-author: Mark Sisson <5761292+marksisson@users.noreply.github.com>
    Co-Authored-By: Mark Sisson <5761292+marksisson@users.noreply.github.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    **Commit 17/23: `ee70922d` (v0.47.0, Advaith Sujith, "fix: canonicalize protected roots at call sites to handle raw paths") — SECURITY ITEM #2 PART 4:**

    ```bash
    git cherry-pick ee70922d
    cargo build --workspace
    git commit --amend -m "$(cat <<'EOF'
    fix: canonicalize protected roots at call sites to handle raw paths

    Upstream-commit: ee70922d
    Upstream-tag: v0.47.0
    Upstream-author: Advaith Sujith <advaith@alwaysfurther.ai>
    Co-Authored-By: Advaith Sujith <advaith@alwaysfurther.ai>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    **Commit 18/23: `f0abd413` (v0.47.0, Leo Lapworth, "feat(profile): #594 phase 2 — canonical JSON schema restructure (#594)") — SECURITY ITEM #3 (largest single commit):**

    23-file canonical-schema restructure. HIGHEST conflict-pressure commit in the chain. D-02 fallback is likely.

    ```bash
    git show f0abd413 --stat
    # Expected: 23 files changed
    git show f0abd413 -- crates/nono-cli/src/profile/   # Read the profile-side diff in full
    git cherry-pick f0abd413
    # D-02 gate: HIGH PROBABILITY of conflicts > 50 lines OR > 2 files. If so:
    #   git cherry-pick --abort
    #   Apply D-20 manual port: read upstream's new canonical schema shape, replay it onto fork's heavily-forked Profile/ProfileDeserialize structs.
    #   Commit body uses "(replayed manually)" suffix on Upstream-commit: line.
    cargo build --workspace
    cargo test -p nono-cli profile::tests::
    # Round-trip parity for ArtifactType::Plugin (Phase 26 PKGS-02):
    cargo test -p nono-cli package::tests::artifact_type_plugin_round_trips
    git commit --amend -m "$(cat <<'EOF'
    feat(profile): #594 phase 2 — canonical JSON schema restructure (#594)

    Fork's ArtifactType::Plugin variant (Phase 26 PKGS-02) round-trips through
    the new canonical schema; serde rename_all = "snake_case" attribute pre-existing.

    Upstream-commit: f0abd413
    Upstream-tag: v0.47.0
    Upstream-author: Leo Lapworth <leo@cuckoo.org>
    Co-Authored-By: Leo Lapworth <leo@cuckoo.org>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    **Commit 19/23: `f3e7f885` (v0.47.0, Matt Palcic, "fix(profile): emit serde-rendered values in show/diff JSON output"):**

    ```bash
    git cherry-pick f3e7f885
    cargo build --workspace
    cargo test -p nono-cli profile::tests::show_diff   # Verify show/diff JSON output tests pass
    git commit --amend -m "$(cat <<'EOF'
    fix(profile): emit serde-rendered values in show/diff JSON output

    Upstream-commit: f3e7f885
    Upstream-tag: v0.47.0
    Upstream-author: Matt Palcic <matt.palcic@naturalforms.com>
    Co-Authored-By: Matt Palcic <matt.palcic@naturalforms.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    Per-task post-check (all 7 commits, 13-19):
    ```bash
    git log --format='%B' HEAD~7..HEAD | grep -c '^Upstream-commit: '   # Expected: 7
    git log --format='%B' HEAD~7..HEAD | grep -c 'Upstream-Author:'     # Expected: 0
    cargo build --workspace
    cargo test --workspace --all-features
    ```
  </action>
  <verify>
    <automated>git log --format='%B' HEAD~7..HEAD | grep -c '^Upstream-commit: ' | grep -E '^7$' &amp;&amp; cargo build --workspace &amp;&amp; cargo test --workspace --all-features</automated>
  </verify>
  <acceptance_criteria>
    - 7 commits landed (bb3f512d, bc443928, be384ee4, dbc10da8, ee70922d, f0abd413, f3e7f885) in chronological order.
    - Each commit body carries verbatim D-19 trailer (lowercase 'a').
    - `grep -c 'validate_path_within' crates/nono-cli/src/policy.rs crates/nono-cli/src/package_cmd.rs` returns the same or higher count than pre-Plan-34-04 baseline.
    - `cargo test -p nono-cli package::tests::artifact_type_plugin_round_trips` exits 0 (Phase 26 PKGS-02 round-trip preserved).
    - Per-commit D-34-E1 invariant check returned 0 for each commit.
    - `cargo test --workspace --all-features` exits 0 within Phase 19 deferred-flake tolerance.
    - If `f0abd413` triggered D-20 manual replay, SUMMARY records the conflict count + the replay approach.
  </acceptance_criteria>
  <done>
    Commits 13-19 landed; canonical JSON schema state established; fork's defense-in-depth preserved.
  </done>
</task>

<task type="auto">
  <name>Task 5: Cherry-pick commits 20-23 (v0.47.1 cluster — release + jsonschema bump + profile drafts + docs)</name>
  <files>
    crates/nono-cli/src/profile/mod.rs
    crates/nono-cli/Cargo.toml
    Cargo.lock
  </files>
  <read_first>
    - crates/nono-cli/Cargo.toml § `jsonschema` line (current version)
    - Cargo.lock § `jsonschema` block (current version)
    - `git show 0cba04a5 7329ef73 829c341a ab74f5cd --stat` (anticipate conflicts; `829c341a` is the largest of the 4 — 9 files)
  </read_first>
  <action>
    **Commit 20/23: `0cba04a5` (v0.47.1, Luke Hinds, "chore: release v0.47.1"):**

    ```bash
    git cherry-pick 0cba04a5
    cargo build --workspace
    git commit --amend -m "$(cat <<'EOF'
    chore: release v0.47.1

    Upstream-commit: 0cba04a5
    Upstream-tag: v0.47.1
    Upstream-author: Luke Hinds <lukehinds@gmail.com>
    Co-Authored-By: Luke Hinds <lukehinds@gmail.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    **Commit 21/23: `7329ef73` (v0.47.1, dependabot[bot], "chore(deps): bump jsonschema from 0.45.1 to 0.46.4"):**

    Cargo.toml + Cargo.lock change. Verify build still passes post-bump.

    ```bash
    git cherry-pick 7329ef73
    cargo build --workspace
    grep 'jsonschema' crates/nono-cli/Cargo.toml   # Expected: jsonschema = "0.46" or similar
    git commit --amend -m "$(cat <<'EOF'
    chore(deps): bump jsonschema from 0.45.1 to 0.46.4

    Upstream-commit: 7329ef73
    Upstream-tag: v0.47.1
    Upstream-author: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>
    Co-Authored-By: dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    **Commit 22/23: `829c341a` (v0.47.1, Luke Hinds, "add commands to manage profile drafts and check package status"):**

    9-file change introducing profile-drafts subcommand. Read carefully.

    ```bash
    git show 829c341a --stat
    git show 829c341a -- crates/   # Read production-code diff in full
    git cherry-pick 829c341a
    # D-02 gate
    cargo build --workspace
    git commit --amend -m "$(cat <<'EOF'
    add commands to manage profile drafts and check package status

    Upstream-commit: 829c341a
    Upstream-tag: v0.47.1
    Upstream-author: Luke Hinds <lukehinds@gmail.com>
    Co-Authored-By: Luke Hinds <lukehinds@gmail.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    **Commit 23/23: `ab74f5cd` (v0.47.1, SequeI, "docs: fix stale references, deprecation wording, and built-in vs pack distinction"):**

    Docs-only.

    ```bash
    git cherry-pick ab74f5cd
    cargo build --workspace
    git commit --amend -m "$(cat <<'EOF'
    docs: fix stale references, deprecation wording, and built-in vs pack distinction

    Upstream-commit: ab74f5cd
    Upstream-tag: v0.47.1
    Upstream-author: SequeI <asiek@redhat.com>
    Co-Authored-By: SequeI <asiek@redhat.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    Plan-close smoke check (D-34-E2):
    ```bash
    git log --format='%B' HEAD~23..HEAD | grep -c '^Upstream-commit: '   # Expected: 23
    git log --format='%B' HEAD~23..HEAD | grep -c 'Upstream-Author:'     # Expected: 0 (case-sensitivity invariant; lowercase 'a' only)
    git log --format='%B' HEAD~23..HEAD | grep -c '^Signed-off-by: '     # Expected: 46 (2 per commit)
    ```
  </action>
  <verify>
    <automated>git log --format='%B' HEAD~23..HEAD | grep -c '^Upstream-commit: ' | grep -E '^23$' &amp;&amp; git log --format='%B' HEAD~23..HEAD | grep -c 'Upstream-Author:' | grep -E '^0$' &amp;&amp; git log --format='%B' HEAD~23..HEAD | grep -c '^Signed-off-by: ' | grep -E '^46$'</automated>
  </verify>
  <acceptance_criteria>
    - 4 commits landed (0cba04a5, 7329ef73, 829c341a, ab74f5cd) in chronological order.
    - `git log --format=%B HEAD~23..HEAD | grep -c '^Upstream-commit: '` returns `23` (full cluster).
    - `git log --format=%B HEAD~23..HEAD | grep -c 'Upstream-Author:'` returns `0`.
    - `git log --format=%B HEAD~23..HEAD | grep -c '^Signed-off-by: '` returns `46`.
    - `grep 'jsonschema' crates/nono-cli/Cargo.toml` shows version 0.46.x.
  </acceptance_criteria>
  <done>
    All 23 C7 cluster commits landed; plan-close smoke check green.
  </done>
</task>

<task type="auto">
  <name>Task 6: D-34-D2 close-gate (8 gates, all blocking)</name>
  <files>(read-only verification)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-D2 (full close-gate text)
    - crates/nono-cli/tests/wfp_port_integration.rs
    - crates/nono-cli/tests/learn_windows_integration.rs
  </read_first>
  <action>
    Run all 8 gates from D-34-D2 in order. Any failure = STOP per D-34-D2 trigger; investigate, either split the plan or roll back to the last clean state.

    1. **Gate 1: Windows-host workspace test:**
       ```
       cargo test --workspace --all-features
       ```
       Expected: exit 0 within Phase 19 deferred-flake tolerance (`tests/env_vars.rs` up to 19 failures, `trust_scan::tests::*` 1–3 failures). NEW failures = STOP.

    2. **Gate 2: Windows-host clippy:**
       ```
       cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used
       ```

    3. **Gate 3: Linux cross-target clippy (CR-A lesson — Phase 25 regression):**
       ```
       cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used
       ```

    4. **Gate 4: macOS cross-target clippy:**
       ```
       cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used
       ```
       Expected: exit 0 (commit 8 `20e2286d` added macOS-gated code; this gate verifies it compiles).

    5. **Gate 5: cargo fmt:**
       ```
       cargo fmt --all -- --check
       ```

    6. **Gate 6: Phase 15 5-row detached-console smoke (Windows host, manual):**
       ```
       nono run --detached --profile default -- powershell -Command "Write-Host 'row1'; Write-Host 'row2'; Write-Host 'row3'; Write-Host 'row4'; Write-Host 'row5'; Start-Sleep 30"
       nono ps                                # Verify session listed
       nono attach <session-id>               # Attach, see 5 rows
       # Ctrl-Q to detach
       nono stop <session-id>                 # Returns 0
       ```
       Expected: 5 rows visible; ps lists session; attach streams; detach works; stop returns 0. Documented-skip if Windows host unavailable.

    7. **Gate 7: WFP port integration (admin + nono-wfp-service):**
       ```
       cargo test -p nono-cli --test wfp_port_integration -- --ignored
       ```
       Documented-skip if admin/service unavailable.

    8. **Gate 8: ETW learn smoke:**
       ```
       cargo test -p nono-cli --test learn_windows_integration
       ```
       Documented-skip if service unavailable.

    9. Verify D-34-E1 invariant holds across the entire 23-commit chain:
       ```
       git log --format='%H' HEAD~23..HEAD | while read sha; do
         git diff --stat $sha^..$sha -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l
       done | sort -u
       # Expected: only "0" appears in the output
       ```

    10. If ANY gate fails: STOP per D-34-D2 trigger. Investigate. Either split the plan into 34-04a + 34-04b (Phase 22-05a/b precedent) OR roll back to the pre-Plan-34-04 HEAD (`git reset --hard <pre-Plan-34-04-HEAD-SHA>` from Task 1 record) and re-scope.
  </action>
  <verify>
    <automated>cargo test --workspace --all-features &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo fmt --all -- --check &amp;&amp; cargo test -p nono-cli --test learn_windows_integration</automated>
  </verify>
  <acceptance_criteria>
    - Gate 1: `cargo test --workspace --all-features` exits 0 within deferred-flake window.
    - Gate 2: Windows-host clippy exits 0.
    - Gate 3: Linux cross-target clippy exits 0.
    - Gate 4: macOS cross-target clippy exits 0.
    - Gate 5: `cargo fmt --all -- --check` exits 0.
    - Gate 6: Phase 15 5-row smoke passes OR documented-skip with rationale.
    - Gate 7: `wfp_port_integration --ignored` passes OR documented-skip.
    - Gate 8: `learn_windows_integration` exits 0.
    - D-34-E1 invariant: across all 23 commits, `git diff --stat` against Windows files returns 0 hits.
  </acceptance_criteria>
  <done>
    Plan 34-04 close-gate cleared. Wave 1 (Plans 34-01, 34-03, 34-06) unblocked per D-34-A2.
  </done>
</task>

<task type="auto">
  <name>Task 7: D-34-D1 plan-close push to origin</name>
  <files>(git push only)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-D1 (direct-on-main; one PR per plan)
  </read_first>
  <action>
    1. Verify origin not ahead of local:
       ```
       git fetch origin
       git log main..origin/main --oneline | wc -l
       # Expected: 0 — if non-zero, STOP (remote raced; investigate)
       ```

    2. Push:
       ```
       git push origin main
       ```

    3. Confirm origin caught up:
       ```
       git fetch origin
       git log origin/main..main --oneline | wc -l   # Expected: 0
       git log -1 origin/main --format='%H'           # Capture for SUMMARY
       ```

    4. Open PR via gh:
       ```
       gh pr create --title "Plan 34-04 (C7): Path canon + canonical JSON schema (v0.46–v0.47.1, 23 commits)" --body "$(cat <<'EOF'
       ## Summary

       Cluster C7 cherry-pick chain — 23 commits from upstream v0.46.0..v0.47.1 covering path canonicalization unification, deny-overlap re-validation, and the canonical JSON profile-schema restructure (`#594 phase 2`). Wave 0 sequential gate for Phase 34; every other will-sync plan rebases on top of this post-C7 state.

       ## Highlights

       - Security item #1: Deny-overlap re-validation (`e2d00546`) composes with fork's `policy.rs::never_grant` (Phase 19) — defense-in-depth preserved.
       - Security item #2: Unified path canonicalization (`bb3f512d`, `69c55f4f`, `dbc10da8`, `ee70922d`, `be384ee4`) — fork's `validate_path_within` retention preserved verbatim; `dunce`-based Windows long-path handling unaffected.
       - Security item #3: Canonical JSON schema restructure (`f0abd413`) — Phase 26 `ArtifactType::Plugin` round-trip preserved.
       - 23 atomic commits with D-19 trailer block (lowercase 'a' in `Upstream-author:`); smoke check confirms 23 trailers in chain.
       - Zero edits to `*_windows.rs` files (D-34-E1 invariant held every commit).
       - `jsonschema` bumped 0.45.1 → 0.46.4 (`7329ef73`).

       ## D-34-D2 close-gate

       - [x] Gate 1: `cargo test --workspace --all-features` (Windows host)
       - [x] Gate 2: Windows-host clippy
       - [x] Gate 3: Linux cross-target clippy
       - [x] Gate 4: macOS cross-target clippy
       - [x] Gate 5: `cargo fmt --all -- --check`
       - [x] Gate 6: Phase 15 5-row detached-console smoke
       - [x] Gate 7: `wfp_port_integration --ignored`
       - [x] Gate 8: `learn_windows_integration`

       🤖 Generated with [Claude Code](https://claude.com/claude-code)
       EOF
       )"
       ```
  </action>
  <verify>
    <automated>git fetch origin &amp;&amp; test "$(git log origin/main..main --oneline | wc -l)" = "0"</automated>
  </verify>
  <acceptance_criteria>
    - `git log origin/main..main --oneline | wc -l` returns `0` post-push.
    - PR URL recorded in SUMMARY.
    - SUMMARY records the post-push origin/main SHA (HEAD of 23-commit chain) for traceability.
  </acceptance_criteria>
  <done>
    Plan 34-04 commits published to origin; PR opened.
  </done>
</task>

</tasks>

<non_goals>
**No Windows-only file touched (D-34-E1).** Any cherry-pick that surfaces a `*_windows.rs` edit is a BUG — abort per D-34-E1 invariant. Plan 34-04 has ZERO Windows file edits.

**No retrofit of upstream features into Windows surface (D-34-B2).** The path-canonicalization helpers `try_canonicalize` etc. are absorbed AS-IS in cross-platform code; fork's `dunce`-based Windows long-path handling is a SEPARATE, parallel mechanism. No "while we're here" Windows wiring.

**No `validate_path_within` removal.** Fork retains this defense-in-depth call at every callsite (Phase 22-03 PKG-04 + Phase 26 PKGS-02 retention). Upstream's new `try_canonicalize` helper composes AS DEFENSE-IN-DEPTH, not as a replacement.

**No POLY-01-stricter regression.** Fork's POLY-01 posture (CONTRADICTION-A from Phase 22 PATTERNS) survives Plan 34-04 — particularly `167b4ea0`'s "relax strict cap check" wording must NOT weaken fork-side strictness.

**No upstream version field sync.** Fork's Cargo.toml version stream is independent of upstream's release-bump commits (`d49585b8`, `7a01e32a`, `0cba04a5`). Preserve fork's version, take upstream's other changes.

**Plan 22-style v0.40.1 fork-baseline.** Phase 34 takes v0.40.1 as the cherry-pick base (Phase 22 UPST2 sync point); commits before that are already in fork. Plan 34-04 covers only the C7 cluster (v0.46.0..v0.47.1).

**No G-25-DRIFT-01 work.** Plan 34-00 (Wave -1) closed G-25-DRIFT-01 as no-divergence; Plan 34-04 does not touch the RESL flag surface.

**No Plan 34-09 / 34-10 manual-replay touches.** C6 packs (Plan 34-09) and C11 proxy TLS (Plan 34-10) live in Wave 3; Plan 34-04 does NOT pre-emptively touch those clusters' surfaces.
</non_goals>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Untrusted profile JSON → Profile struct | User-supplied profile JSON crosses into `serde_json::from_str` → `ProfileDeserialize::deserialize`. The canonical-schema restructure (`f0abd413`) changes this serialization shape. |
| Path string → canonicalized path | Cluster C7 introduces `try_canonicalize` helper. Paths cross the unsafe canonicalization boundary (symlink resolution, ancestor-walk). |
| Capability dedup → policy resolver | `dbc10da8` introduces platform-specific dedup key behavior. Windows arm must not regress. |
| Cross-platform crate → upstream library | `jsonschema` 0.46.4 bump (`7329ef73`) crosses the dependency-trust boundary. |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation |
|-----------|----------|-----------|----------|-------------|------------|
| T-34-04-01 | Tampering | Cherry-pick silently drops `validate_path_within` calls (fork defense-in-depth) | **high** | mitigate (BLOCKING) | Tasks 2-5 per-commit acceptance criteria explicitly grep `validate_path_within` callsite count and assert preservation. Phase 33 fork-divergence catalog § `validate_path_within` defense-in-depth retention referenced in commit body when relevant. |
| T-34-04-02 | Elevation of Privilege | D-21 Windows-only files invariant violation (commit touches `*_windows.rs` outside intended scope) | **high** | mitigate (BLOCKING) | Per-commit D-34-E1 invariant check (`git diff --stat HEAD~1 HEAD -- crates/ \| grep -E '_windows\|exec_strategy_windows'`) MUST return 0. Failure = abort, revert Windows hunk, re-cherry-pick. |
| T-34-04-03 | Repudiation | D-19 trailer block tampered or missing (no `Upstream-commit:`, no DCO sign-off, or uppercase 'A' in `Upstream-Author:`) | **high** | mitigate (BLOCKING) | Task 5 plan-close smoke check: `grep -c '^Upstream-commit: '` == 23, `grep -c 'Upstream-Author:'` == 0, `grep -c '^Signed-off-by: '` == 46. Per-commit acceptance criteria enforce the same. |
| T-34-04-04 | Tampering | Path-traversal regression on C7 canonicalization absorption (upstream's `try_canonicalize` composes incorrectly with fork's `validate_path_within`) | **high** | mitigate (BLOCKING) | Port upstream's path-canonicalization regression tests verbatim (D-34-E4); cross-check that fork's `validate_path_within` callsites compose with upstream's new helper (do not silently delete fork's call sites). Task 4 `bb3f512d` resolution preserves fork callsites. |
| T-34-04-05 | Information Disclosure | Canonical JSON schema serializes a fork-only field with insecure default (e.g., `ArtifactType::Plugin` exposed before Phase 26 PKGS-02 contract validates it) | medium | mitigate | Task 4 `f0abd413` verifies round-trip parity for ALL fork-side enum variants via `artifact_type_plugin_round_trips` test (Phase 26 PKGS-02 acceptance criterion). |
| T-34-04-06 | Tampering | POLY-01-stricter regression (`167b4ea0` "relax strict cap check" weakens fork posture) | medium | mitigate | Task 3 Commit 6 acceptance criteria includes `cargo test -p nono-cli policy::tests::` POLY-01 regression sentinel. If POLY-01 weakens, document in commit body and SUMMARY (Plan 22 PATTERNS CONTRADICTION-A precedent). |
| T-34-04-07 | Elevation of Privilege | `dbc10da8` platform-specific dedup key leaves Windows arm uncovered (default-fallthrough behavior may differ from fork's current dunce-based dedup) | medium | mitigate | Task 4 Commit 16 acceptance criteria verifies Windows arm preserved per fork's current behavior; cargo test capability::tests:: passes. |
| T-34-04-08 | Tampering | `jsonschema 0.46.4` bump introduces a behavioral regression in profile-schema validation | low | accept | Upstream's release notes + community trust signal. Task 5 Commit 21 verifies `cargo build --workspace` + `cargo test --workspace --all-features` post-bump. |

**BLOCKING threats:** T-34-04-01, T-34-04-02, T-34-04-03, T-34-04-04 — all four block plan-close until mitigations are demonstrably present.
</threat_model>

<verification>
Per-plan close gate (D-34-D2):

- `cargo test --workspace --all-features` exits 0 within Phase 19 deferred-flake tolerance.
- `cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used` (Windows host) exits 0.
- `cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` exits 0.
- `cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used` exits 0.
- `cargo fmt --all -- --check` exits 0.
- Phase 15 5-row detached-console smoke gate passes (or documented-skip).
- `cargo test -p nono-cli --test wfp_port_integration -- --ignored` passes (or documented-skip).
- `cargo test -p nono-cli --test learn_windows_integration` exits 0.
- `git log --format='%B' HEAD~23..HEAD | grep -c '^Upstream-commit: '` returns `23`.
- `git log --format='%B' HEAD~23..HEAD | grep -c 'Upstream-Author:'` returns `0`.
- `git log --format='%B' HEAD~23..HEAD | grep -c '^Signed-off-by: '` returns `46`.
- Per-commit D-34-E1 invariant: across all 23 commits, `git diff --stat <prev>..<this> -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l` returns `0`.
- `grep -c 'validate_path_within' crates/nono-cli/src/policy.rs crates/nono-cli/src/package_cmd.rs` returns the same or higher count than pre-Plan-34-04 baseline (fork defense-in-depth preserved).
- `cargo test -p nono-cli package::tests::artifact_type_plugin_round_trips` exits 0 (Phase 26 PKGS-02 round-trip preserved post-`f0abd413`).
- `git log origin/main..main --oneline | wc -l` returns `0` post-push.
</verification>

<success_criteria>
- 23 atomic commits on `main` (commits 1-23 from cluster C7 table), each carrying verbatim D-19 6-line trailer.
- Path canonicalization unified via `try_canonicalize` helper in `diagnostic.rs`; fork's `dunce`-based Windows long-path handling preserved.
- Canonical JSON profile schema landed; `ProfileDeserialize` companion struct updated; `ArtifactType::Plugin` round-trip preserved.
- Deny-overlap re-validation (`e2d00546`) composes with fork's `policy.rs::never_grant`; both defenses fire.
- `jsonschema` bumped 0.45.1 → 0.46.4.
- All 8 D-34-D2 close-gates green (or documented-skip with rationale for Gates 6-8).
- Zero edits to `*_windows.rs` files; D-34-E1 invariant held per commit.
- `make ci` green or matches Phase 19 deferred window.
- `origin/main` advanced to plan-close HEAD; PR opened via `gh pr create`.
- Wave 1 (Plans 34-01, 34-03, 34-06) unblocked per D-34-A2.
- Plan SUMMARY records 23 commit hashes, the pre-Plan-34-04 HEAD SHA, the post-push origin/main SHA, the PR URL, any D-20 manual-replay rationale (likely for `f0abd413`), and explicit D-34-E1 invariant check results.
</success_criteria>

<output>
After completion, create `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-04-SUMMARY.md` using the standard summary template. Required sections: Outcome ("C7 path canon + canonical JSON schema landed; Wave 0 gate cleared; Wave 1 unblocked"), What was done (one bullet per task), Verification table (8 close-gates with actual results), Files changed (6-8 cross-platform files; zero Windows files), Commits (23-row table: SHA + subject + upstream tag + upstream author), Status (complete), Deferred (any D-20 manual replays + their rationale; any documented-skip gates).
</output>
