---
phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
plan_number: 34-06
plan: 06
slug: trust-scan
cluster_id: C9
type: execute
wave: 1
depends_on: ["34-04"]
blocks: []
files_modified:
  - crates/nono/src/trust/scan.rs
  - crates/nono-cli/src/trust_cmd.rs
  - crates/nono-cli/src/wiring.rs
  - Cargo.toml
  - Cargo.lock
upstream_tag_range: v0.49.0
upstream_commit_count: 8
autonomous: true
requirements: [C9]
tags: [upst3, c9, trust-scan, path-traversal, yaml-merge, wave-1]

must_haves:
  truths:
    - "All 8 cluster-C9 commits cherry-picked onto `main` in upstream chronological order"
    - "Every Plan 34-06 commit body carries the verbatim D-19 6-line trailer block"
    - "Symlink-escape (`cd4fd982`) + path-traversal (`fdef1335`) rejected in trust-scan multi-subject bundle subject names (security item)"
    - "Empty parent() treated as CWD when deriving scan_root (`4f8c332c`) — Windows path-semantics relevant"
    - "`yaml_merge` wiring directive landed (`d44f5541`); `serde_yaml_ng` pinned to 0.10.0 (`242d4917`)"
    - "Fork's Phase 32 Sigstore TUF cached-root path composes cleanly with upstream's trust-scan hardening (no regression to `bundle.rs::load_production_trusted_root`)"
    - "Upstream regression tests for symlink-escape + path-traversal ported alongside production code (D-34-E4)"
    - "D-34-E1 invariant: zero edits to `*_windows.rs` for every commit"
    - "All 8 D-34-D2 close-gates pass"
  artifacts:
    - path: "crates/nono/src/trust/scan.rs"
      provides: "Symlink-escape rejection (`cd4fd982`); path-traversal rejection (`fdef1335`); empty-parent CWD derivation (`4f8c332c`)"
      grep_pattern: "scan_root|symlink_escape|reject_traversal"
    - path: "crates/nono-cli/src/wiring.rs"
      provides: "yaml_merge directive (`d44f5541`)"
      grep_pattern: "yaml_merge"
    - path: "Cargo.toml + Cargo.lock"
      provides: "serde_yaml_ng pinned to 0.10.0 (`242d4917`)"
      grep_pattern: "serde_yaml_ng.*=.*\"0\\.10\\.0\""
  key_links:
    - from: "Fork's Phase 32 Sigstore TUF cached-root (`load_production_trusted_root`)"
      to: "Upstream's trust-scan hardening"
      via: "compose cleanly — both layers fire; no `load_production_trusted_root` deletion or signature change"
      pattern: "load_production_trusted_root"
    - from: "User-supplied multi-subject bundle (symlink-escape vector)"
      to: "trust::scan rejection path"
      via: "fail-closed on path components matching `..` OR resolving via symlink outside scan_root"
      pattern: "PathBuf::components|symlink.*reject|traversal.*reject"
---

<objective>
Cluster C9 (upstream v0.49.0, 8 commits): trust-scan symlink-escape + path-traversal hardening, plus yaml_merge wiring directive + serde_yaml_ng pin. Two security fixes (`cd4fd982`, `fdef1335`) close real validation gaps in the trust subsystem the fork's Phase 32 Sigstore TUF work consumes.

Output: 8 atomic commits with D-19 trailers. Trust-scan hardened; `yaml_merge` directive landed for fork users patching upstream profiles via YAML overlay.
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
@crates/nono/src/trust/scan.rs
@crates/nono/src/trust/bundle.rs

<interfaces>
**Cluster C9 cherry-pick chain (8 commits, chronological):**

| Order | SHA | Tag | Subject | Upstream Author |
|-------|-----|-----|---------|-----------------|
| 1 | `242d4917` | v0.49.0 | fix(yaml-merge): pin serde_yaml_ng to 0.10.0 and add reversal failure test | Luke Hinds <lukehinds@gmail.com> |
| 2 | `4f8c332c` | v0.49.0 | fix(trust): treat empty parent() as CWD when deriving scan_root | Luke Hinds <lukehinds@gmail.com> |
| 3 | `802c8566` | v0.49.0 | style: apply rustfmt | Advaith Sujith <advaith@alwaysfurther.ai> |
| 4 | `cd4fd982` | v0.49.0 | fix(trust): reject symlink-escape in multi-subject bundle subject names | Luke Hinds <lukehinds@gmail.com> |
| 5 | `ce3230d8` | v0.49.0 | style: apply rustfmt to trust_cmd and trust_scan | Luke Hinds <lukehinds@gmail.com> |
| 6 | `d44f5541` | v0.49.0 | feat(wiring): add yaml_merge directive for YAML config patching | Advaith Sujith <advaith@alwaysfurther.ai> |
| 7 | `fdef1335` | v0.49.0 | fix(trust): reject path traversal in multi-subject bundle subject names | Luke Hinds <lukehinds@gmail.com> |
| 8 | `587d98de` | v0.49.0 | chore: release v0.49.0 | Luke Hinds <lukehinds@gmail.com> |

**Note on chronological order:** DIVERGENCE-LEDGER.md lists C9 commits alphabetically; the chronological order above follows upstream's actual commit topology in v0.49.0 (verify via `git log --topo-order upstream/v0.48.0..upstream/v0.49.0`).

**D-19 trailer block + per-commit template** — same as Plan 34-01.

**Fork-divergence catalog cross-checks:**

- **Phase 32 Sigstore TUF cached-root**: fork's `bundle.rs::load_production_trusted_root` is post-v0.40 fork-only surface. Cluster C9 touches `trust/scan.rs` but NOT `trust/bundle.rs`. Verify after every commit:
  ```
  git diff --stat HEAD~1 HEAD -- crates/nono/src/trust/bundle.rs | wc -l
  # Expected: 0 (bundle.rs is fork-only post-v0.40; C9 should not touch it)
  ```

- **Windows path semantics for empty-parent CWD derivation** (`4f8c332c`): upstream's fix treats empty `Path::parent()` result as CWD. Windows path edge cases (drive letters, UNC roots) behave differently from POSIX. Verify after commit 2 that fork's trust-scan tests pass on Windows.

- **CLAUDE.md path-component comparison rule**: any path comparisons in `cd4fd982` + `fdef1335` MUST use `Path::components()` iteration, NOT string `starts_with()`. Read upstream's diff carefully; if upstream uses string ops, document as a deviation candidate (D-20 manual port).
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Pre-flight + capture pre-Plan-34-06 state</name>
  <files>(git operations only)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-A2
    - crates/nono/src/trust/bundle.rs (fork-only; document as post-v0.40 surface)
  </read_first>
  <action>
    1. Verify Plan 34-04 closed.
    2. `git fetch upstream --tags`.
    3. Verify all 8 C9 SHAs reachable.
    4. Capture pre-Plan-34-06 HEAD + trust/bundle.rs sha (must NOT change post-plan):
       ```
       git log -1 --format='%H'   # Pre-plan HEAD
       git log -1 --format='%H' -- crates/nono/src/trust/bundle.rs   # Pre-plan bundle.rs last-touched commit
       ```
    5. Baseline build + trust tests:
       ```
       cargo build --workspace
       cargo test -p nono trust::tests::
       ```
  </action>
  <verify>
    <automated>git fetch upstream --tags &amp;&amp; cargo build --workspace &amp;&amp; cargo test -p nono trust::tests::</automated>
  </verify>
  <acceptance_criteria>
    - Plan 34-04 closed; 8 C9 SHAs reachable; baseline trust tests green; pre-state captured.
  </acceptance_criteria>
  <done>
    Ready for C9 chain.
  </done>
</task>

<task type="auto">
  <name>Task 2: Cherry-pick all 8 C9 commits with D-19 trailers (security items inline)</name>
  <files>
    crates/nono/src/trust/scan.rs
    crates/nono-cli/src/trust_cmd.rs
    crates/nono-cli/src/wiring.rs
    Cargo.toml
    Cargo.lock
  </files>
  <read_first>
    - crates/nono/src/trust/scan.rs § current scan_root derivation logic
    - crates/nono-cli/src/wiring.rs (current wiring-directive registry)
    - `git show 242d4917 4f8c332c 802c8566 cd4fd982 ce3230d8 d44f5541 fdef1335 587d98de --stat`
    - CLAUDE.md § Security Considerations § Path Handling (path-component comparison; string starts_with is a footgun)
  </read_first>
  <action>
    For each of the 8 commits, follow the per-commit pattern.

    **Critical attention point for commits 4 + 7 (security items `cd4fd982` + `fdef1335`):**

    Read upstream's diff carefully BEFORE cherry-pick:
    ```bash
    git show cd4fd982 -- crates/nono/src/trust/scan.rs
    git show fdef1335 -- crates/nono/src/trust/scan.rs
    # Verify: rejection uses Path::components() iteration, NOT string starts_with().
    # If upstream's diff uses string ops, RECORD the deviation in SUMMARY and STOP — this requires fork-side adaptation to use component iteration (CLAUDE.md path-handling policy).
    ```

    **Critical attention point for commit 2 (`4f8c332c`):**

    Empty `Path::parent()` on Windows can return `Some("")` (empty string) for drive-letter roots like `C:\foo.txt`. Verify Windows behavior:
    ```bash
    # After cherry-picking 4f8c332c:
    cargo test -p nono trust::tests::scan_root_   # Verify scan_root tests pass on Windows
    ```

    **Critical attention point for commit 6 (`d44f5541` yaml_merge directive):**

    Wiring directives compose with fork's existing wiring registry. Verify after commit:
    ```bash
    grep -c 'yaml_merge' crates/nono-cli/src/wiring.rs   # Expected: ≥ 1
    cargo test -p nono-cli wiring::tests::
    ```

    **Per-commit template:**

    ```bash
    git cherry-pick <sha>
    cargo build --workspace
    git commit --amend -m "$(cat <<'EOF'
    <upstream subject verbatim>

    <upstream body if present>

    Upstream-commit: <8-char sha>
    Upstream-tag: v0.49.0
    Upstream-author: <name> <<email>>
    Co-Authored-By: <name> <<email>>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    git diff --stat HEAD~1 HEAD -- crates/nono/src/trust/bundle.rs | wc -l                       # Expected: 0 (fork-only file untouched)
    ```

    After all 8:
    ```bash
    git log --format='%B' HEAD~8..HEAD | grep -c '^Upstream-commit: '   # Expected: 8
    git log --format='%B' HEAD~8..HEAD | grep -c 'Upstream-Author:'     # Expected: 0
    git log --format='%B' HEAD~8..HEAD | grep -c '^Signed-off-by: '     # Expected: 16

    # Verify trust/bundle.rs untouched:
    git log -1 --format='%H' -- crates/nono/src/trust/bundle.rs
    # Should equal the pre-Plan-34-06 SHA captured in Task 1
    ```
  </action>
  <verify>
    <automated>git log --format='%B' HEAD~8..HEAD | grep -c '^Upstream-commit: ' | grep -E '^8$' &amp;&amp; cargo build --workspace &amp;&amp; cargo test -p nono trust::tests:: &amp;&amp; grep -c 'yaml_merge' crates/nono-cli/src/wiring.rs</automated>
  </verify>
  <acceptance_criteria>
    - 8 commits with D-19 trailers (lowercase 'a').
    - Per-commit D-34-E1 invariant returned 0.
    - Per-commit `trust/bundle.rs` untouched (fork-only Phase 32 surface preserved).
    - Trust-scan tests pass (existing + ported regression tests for symlink-escape + path-traversal).
    - `grep 'yaml_merge' crates/nono-cli/src/wiring.rs` returns ≥ 1.
    - `grep 'serde_yaml_ng.*0\.10\.0' Cargo.toml` (or appropriate Cargo.toml) returns 1.
  </acceptance_criteria>
  <done>
    C9 cherry-pick chain complete; trust subsystem hardened; bundle.rs untouched.
  </done>
</task>

<task type="auto">
  <name>Task 3: D-34-D2 close-gate (8 gates)</name>
  <files>(read-only verification)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-D2
  </read_first>
  <action>
    Run all 8 close-gates. Verify D-34-E1 invariant + `trust/bundle.rs` untouched across the 8-commit chain.
  </action>
  <verify>
    <automated>cargo test --workspace --all-features &amp;&amp; cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo clippy --workspace --all-targets --target x86_64-apple-darwin -- -D warnings -D clippy::unwrap_used &amp;&amp; cargo fmt --all -- --check</automated>
  </verify>
  <acceptance_criteria>
    - All 8 close-gates pass (or documented-skip).
    - D-34-E1 invariant: 0 hits.
  </acceptance_criteria>
  <done>
    Plan 34-06 close-gate cleared.
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
    2. `gh pr create --title "Plan 34-06 (C9): Trust-scan hardening + yaml_merge directive (v0.49.0, 8 commits)"`.
  </action>
  <verify>
    <automated>git fetch origin &amp;&amp; test "$(git log origin/main..main --oneline | wc -l)" = "0"</automated>
  </verify>
  <acceptance_criteria>
    - Pushed; PR opened.
  </acceptance_criteria>
  <done>
    Plan 34-06 published.
  </done>
</task>

</tasks>

<non_goals>
**No `trust/bundle.rs` touched.** Phase 32's `load_production_trusted_root` is fork-only post-v0.40 surface and stays byte-identical.

**No `*_windows.rs` touched.**

**No fork-only path-component comparison changes.** Fork already uses `Path::components()` for path traversal checks; if upstream's commit accidentally introduces string `starts_with()` ops, RECORD the deviation in SUMMARY and use D-20 manual port to substitute component-iteration.

**No Sigstore TUF cached-root changes.** Phase 32's broker self-trust-anchor + cached-root pattern stays intact.
</non_goals>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| User-supplied multi-subject bundle subject name → trust-scan path resolution | Symlink-escape + path-traversal vectors. |
| YAML config overlay → wiring directive consumer | `yaml_merge` introduces a new patching primitive. |
| serde_yaml_ng dep upgrade → YAML parser | Pinned at 0.10.0 to guard against serde_yaml deprecation. |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation |
|-----------|----------|-----------|----------|-------------|------------|
| T-34-06-01 | Tampering | D-21 Windows-only files invariant violation | **high** | mitigate (BLOCKING) | Per-commit D-34-E1 invariant. |
| T-34-06-02 | Repudiation | D-19 trailer missing | **high** | mitigate (BLOCKING) | Task 2 plan-close smoke. |
| T-34-06-03 | Tampering | trust-scan symlink-escape regression on Windows (UNC, `\\?\`, drive-letter forms not handled by upstream's POSIX-centric pattern) | **high** | mitigate (BLOCKING) | Port upstream's symlink-escape fixture (D-34-E4); add Windows extension test under `#[cfg(target_os = "windows")]`. |
| T-34-06-04 | Tampering | `bundle.rs::load_production_trusted_root` (Phase 32 fork-only) silently modified by cluster cherry-pick | **high** | mitigate (BLOCKING) | Per-commit `git diff --stat HEAD~1 HEAD -- crates/nono/src/trust/bundle.rs` returns 0. |
| T-34-06-05 | Tampering | Upstream uses string `starts_with()` in path-traversal check (CLAUDE.md footgun) | medium | mitigate | Task 2 reads upstream diff for `cd4fd982` + `fdef1335` BEFORE cherry-pick; if string ops detected, switch to D-20 manual port with `Path::components()` iteration. |
| T-34-06-06 | Tampering | `yaml_merge` directive (`d44f5541`) allows untrusted YAML overlay to clobber security-relevant config | medium | accept | Wiring-directive compositional model already requires trust at the directive-author boundary; YAML merge is a configuration primitive, not a privilege gate. Fork's wiring registry tests cover the directive shape. |
| T-34-06-07 | Information Disclosure | Empty-parent CWD derivation (`4f8c332c`) leaks CWD path into trust-scan rejection error message (potential PII for user-home paths) | low | accept | Standard nono error-output redaction applies to file-path error messages. |
| T-34-06-08 | Denial of Service | `serde_yaml_ng 0.10.0` pin breaks downstream consumers expecting a different version | low | accept | Cargo.lock resolution will surface conflicts; upstream's pin reasoning is documented in the commit body. |
</threat_model>

<verification>
- All 8 D-34-D2 close-gates pass.
- `git log --format='%B' HEAD~8..HEAD | grep -c '^Upstream-commit: '` returns `8`.
- `git log --format='%B' HEAD~8..HEAD | grep -c '^Signed-off-by: '` returns `16`.
- Per-commit D-34-E1 invariant: 0 hits.
- Per-commit `trust/bundle.rs` untouched.
- `grep -c 'yaml_merge' crates/nono-cli/src/wiring.rs` returns ≥ 1.
- Trust-scan symlink-escape + path-traversal regression tests pass (ported per D-34-E4).
</verification>

<success_criteria>
- 8 atomic commits on `main`, each with D-19 trailer.
- Trust-scan hardened against symlink-escape + path-traversal in multi-subject bundles.
- `yaml_merge` directive landed; `serde_yaml_ng` pinned.
- Phase 32 fork-only surface (`trust/bundle.rs`) untouched.
- All 8 D-34-D2 gates green.
- `origin/main` advanced; PR opened.
</success_criteria>

<output>
After completion, create `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-06-SUMMARY.md`.
</output>
