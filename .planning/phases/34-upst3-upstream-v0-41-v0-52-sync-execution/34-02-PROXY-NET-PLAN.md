---
phase: 34-upst3-upstream-v0-41-v0-52-sync-execution
plan_number: 34-02
plan: 02
slug: proxy-net
cluster_id: C4
type: execute
wave: 2
depends_on: ["34-04", "34-01"]
blocks: ["34-10"]
files_modified:
  - crates/nono-proxy/src/server.rs
  - crates/nono-proxy/src/filter.rs
  - crates/nono-cli/src/cli.rs
  - crates/nono-cli/src/profile/mod.rs
  - crates/nono/src/capability.rs
upstream_tag_range: v0.42.0..v0.45.0
upstream_commit_count: 4
autonomous: true
requirements: [C4]
tags: [upst3, c4, proxy, network, allow-connect-port, wave-2]

must_haves:
  truths:
    - "All 4 cluster-C4 commits cherry-picked onto `main` in upstream chronological order"
    - "Every Plan 34-02 commit body carries the verbatim D-19 6-line trailer block"
    - "`ad23d794` — stop adding allow_domain hosts to NO_PROXY without direct TCP grants (closes silent-bypass hole)"
    - "`8c818f84` — `--allow-connect-port` flag for outbound TCP port allowlisting (proxy-only per D-34-B2; NO Phase 09 WFP retrofit)"
    - "`cba186f4` — macOS fail-fast on `--allow-connect-port` (1-line guard)"
    - "`cb6b199c` — native TLS root certificates for package downloads"
    - "D-34-B2 surgical posture: `--allow-connect-port` does NOT wire into Phase 09 WFP port-level filter; remains proxy-only enforcement"
    - "D-34-E1 invariant: zero edits to `*_windows.rs` for every commit"
    - "All 8 D-34-D2 close-gates pass"
  artifacts:
    - path: "crates/nono-proxy/src/server.rs"
      provides: "NO_PROXY hole fix (`ad23d794`); native TLS roots for package downloads (`cb6b199c`)"
      grep_pattern: "NO_PROXY|native_tls|rustls.*native"
    - path: "crates/nono-cli/src/cli.rs"
      provides: "`--allow-connect-port` flag (`8c818f84`); macOS fail-fast guard (`cba186f4`)"
      grep_pattern: "allow_connect_port|allow-connect-port"
  key_links:
    - from: "User running `nono run --allow-connect-port 443 -- <cmd>`"
      to: "nono-proxy outbound-TCP allowlist (proxy-only)"
      via: "no fork-side WFP retrofit per D-34-B2; Phase 09 `--allow-port` remains a SEPARATE, parallel enforcement layer"
      pattern: "allow_connect_port.*proxy|outbound.*tcp"
---

<objective>
Cluster C4 (upstream v0.42.0..v0.45.0, 4 commits): proxy/network policy hardening with three behavioral fixes — NO_PROXY hole closure, `--allow-connect-port` flag, native TLS roots for package downloads. macOS fail-fast guard rides along.

**Critical D-34-B2 posture:** `--allow-connect-port` flows through `nono-proxy` ONLY. NO fork-side wiring to Phase 09 WFP port-level filter. The two enforcement layers (proxy CONNECT-port and WFP `--allow-port`) remain parallel; users wanting kernel-level port allowlisting still use Phase 09's `--allow-port` (Windows-only). This avoids load-bearing composition the fork would own forever.

Output: 4 atomic commits with D-19 trailers; surgical posture documented in commit body for `8c818f84`.
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
@crates/nono-proxy/src/server.rs

<interfaces>
**Cluster C4 cherry-pick chain (4 commits, chronological):**

| Order | SHA | Tag | Subject | Upstream Author |
|-------|-----|-----|---------|-----------------|
| 1 | `ad23d794` | v0.42.0 | fix(proxy): stop adding allow_domain hosts to NO_PROXY without direct TCP grants | 407 <g4x0v7@gmail.com> |
| 2 | `8c818f84` | v0.43.0 | feat(cli): add --allow-connect-port for outbound TCP port allowlisting | Arnaud Sahuguet <sahuguet@users.noreply.github.com> |
| 3 | `cba186f4` | v0.43.0 | fix(cli): fail fast on --allow-connect-port on macOS | Arnaud Sahuguet <sahuguet@users.noreply.github.com> |
| 4 | `cb6b199c` | v0.45.0 | feat(packages): use native tls root certificates | Luke Hinds <lukehinds@gmail.com> |

**Plan dependency note:** Wave 2 plans (34-02, 34-05, 34-07, 34-08) all touch `cli.rs`. To avoid same-file conflicts, this plan depends on Plan 34-01 (Wave 1, C2 CLI consolidation) which restructures `cli.rs` first. Other Wave 2 plans should serialize their `cli.rs` touches by upstream chronological order (C4 v0.42-v0.45 < C8 v0.48 < C10 v0.50 < C12 v0.52).

**D-34-B2 commit-body specifics for `8c818f84`:**

```
feat(cli): add --allow-connect-port for outbound TCP port allowlisting

Per Phase 34 D-34-B2 surgical retrofit posture: --allow-connect-port flows
through nono-proxy ONLY. NO fork-side wiring to Phase 09 WFP port-level
filter. Phase 09 --allow-port remains a SEPARATE, parallel kernel-enforced
layer for Windows users; users on other platforms get proxy-only enforcement.
This avoids load-bearing composition the fork would own forever.

Upstream-commit: 8c818f84
Upstream-tag: v0.43.0
Upstream-author: Arnaud Sahuguet <sahuguet@users.noreply.github.com>
Co-Authored-By: Arnaud Sahuguet <sahuguet@users.noreply.github.com>
Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
```

**Fork-divergence catalog:**

- **Phase 09 WFP `--allow-port` (Windows-only)**: remains untouched. Plan 34-02 explicitly does NOT compose `--allow-connect-port` with WFP. Verify after commit 2:
  ```
  git diff --stat HEAD~1 HEAD -- crates/nono-cli/src/exec_strategy_windows/ | wc -l
  # Expected: 0 (no WFP retrofit)
  ```

- **`nono-proxy` Windows credential-injection rewrite** (Phase 09 + Phase 11): cluster C11 (Plan 34-10) manual replays around this. C4 absorbs upstream's NO_PROXY + TLS-roots fixes WITHOUT touching the Windows credential-injection paths.
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Pre-flight — verify Wave 0 + Plan 34-01 closed</name>
  <files>(git operations only)</files>
  <read_first>
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-A2 (Wave 2 depends on Wave 1)
  </read_first>
  <action>
    1. Verify Plans 34-04 + 34-01 closed (cli.rs has `nono profile` subcommand from 34-01; canonical schema from 34-04).
    2. `git fetch upstream --tags`.
    3. Verify all 4 C4 SHAs reachable.
    4. Capture pre-Plan-34-02 HEAD + verify exec_strategy_windows/ untouched baseline:
       ```
       git log -1 --format='%H' -- crates/nono-cli/src/exec_strategy_windows/   # Record for post-plan compare
       ```
    5. `cargo build --workspace`.
  </action>
  <verify>
    <automated>git fetch upstream --tags &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - Plan 34-04 + Plan 34-01 closed; 4 C4 SHAs reachable; pre-state captured; baseline build green.
  </acceptance_criteria>
  <done>
    Ready for C4 chain.
  </done>
</task>

<task type="auto">
  <name>Task 2: Cherry-pick all 4 C4 commits with D-19 trailers + surgical-posture note for 8c818f84</name>
  <files>
    crates/nono-proxy/src/server.rs
    crates/nono-proxy/src/filter.rs
    crates/nono-cli/src/cli.rs
    crates/nono-cli/src/profile/mod.rs
    crates/nono/src/capability.rs
  </files>
  <read_first>
    - crates/nono-proxy/src/server.rs § current NO_PROXY logic + TLS root config
    - crates/nono-cli/src/cli.rs § post-Plan-34-01 `Commands::Profile` shape (where `--allow-connect-port` lands)
    - `git show ad23d794 8c818f84 cba186f4 cb6b199c --stat`
    - .planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-CONTEXT.md § D-34-B2 (surgical retrofit posture)
  </read_first>
  <action>
    **Commit 1/4: `ad23d794` (407, "fix(proxy): stop adding allow_domain hosts to NO_PROXY without direct TCP grants"):**

    ```bash
    git cherry-pick ad23d794
    cargo build --workspace
    git commit --amend -m "$(cat <<'EOF'
    fix(proxy): stop adding allow_domain hosts to NO_PROXY without direct TCP grants

    Upstream-commit: ad23d794
    Upstream-tag: v0.42.0
    Upstream-author: 407 <g4x0v7@gmail.com>
    Co-Authored-By: 407 <g4x0v7@gmail.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    **Commit 2/4: `8c818f84` (Arnaud Sahuguet, "feat(cli): add --allow-connect-port for outbound TCP port allowlisting") — D-34-B2 SURGICAL POSTURE COMMIT:**

    ```bash
    git cherry-pick 8c818f84
    cargo build --workspace
    # Verify NO WFP retrofit:
    git diff --stat HEAD~1 HEAD -- crates/nono-cli/src/exec_strategy_windows/ | wc -l   # Expected: 0
    grep -c 'allow_connect_port.*wfp\|wfp.*allow_connect_port' crates/nono-cli/src/   # Expected: 0 (NO WFP wiring)
    git commit --amend -m "$(cat <<'EOF'
    feat(cli): add --allow-connect-port for outbound TCP port allowlisting

    Per Phase 34 D-34-B2 surgical retrofit posture: --allow-connect-port
    flows through nono-proxy ONLY. NO fork-side wiring to Phase 09 WFP
    port-level filter. Phase 09 --allow-port remains a SEPARATE, parallel
    kernel-enforced layer for Windows users.

    Upstream-commit: 8c818f84
    Upstream-tag: v0.43.0
    Upstream-author: Arnaud Sahuguet <sahuguet@users.noreply.github.com>
    Co-Authored-By: Arnaud Sahuguet <sahuguet@users.noreply.github.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    ```

    **Commit 3/4: `cba186f4` (Arnaud Sahuguet, "fix(cli): fail fast on --allow-connect-port on macOS"):**

    ```bash
    git cherry-pick cba186f4
    cargo build --workspace
    cargo build --workspace --target x86_64-apple-darwin   # Verify macOS gate compiles
    git commit --amend -m "$(cat <<'EOF'
    fix(cli): fail fast on --allow-connect-port on macOS

    Upstream-commit: cba186f4
    Upstream-tag: v0.43.0
    Upstream-author: Arnaud Sahuguet <sahuguet@users.noreply.github.com>
    Co-Authored-By: Arnaud Sahuguet <sahuguet@users.noreply.github.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    **Commit 4/4: `cb6b199c` (Luke Hinds, "feat(packages): use native tls root certificates"):**

    Native TLS roots in package downloads. Important for fork's headless/MSI Windows installs (no system rustls trust bundle assumed).

    ```bash
    git cherry-pick cb6b199c
    cargo build --workspace
    git commit --amend -m "$(cat <<'EOF'
    feat(packages): use native tls root certificates

    Upstream-commit: cb6b199c
    Upstream-tag: v0.45.0
    Upstream-author: Luke Hinds <lukehinds@gmail.com>
    Co-Authored-By: Luke Hinds <lukehinds@gmail.com>
    Signed-off-by: Oscar Mack <oscar.mack.jr@gmail.com>
    Signed-off-by: oscarmackjr-twg <oscar.mack.jr@gmail.com>
    EOF
    )"
    git diff --stat HEAD~1 HEAD -- crates/ | grep -E '_windows|exec_strategy_windows' | wc -l   # Expected: 0
    ```

    After all 4:
    ```bash
    git log --format='%B' HEAD~4..HEAD | grep -c '^Upstream-commit: '   # Expected: 4
    git log --format='%B' HEAD~4..HEAD | grep -c '^Signed-off-by: '     # Expected: 8

    # D-34-B2 surgical posture verification:
    git log -1 --format='%H' -- crates/nono-cli/src/exec_strategy_windows/
    # Must equal the pre-Plan-34-02 SHA from Task 1
    ```
  </action>
  <verify>
    <automated>git log --format='%B' HEAD~4..HEAD | grep -c '^Upstream-commit: ' | grep -E '^4$' &amp;&amp; cargo build --workspace</automated>
  </verify>
  <acceptance_criteria>
    - 4 commits with D-19 trailers (lowercase 'a').
    - Per-commit D-34-E1 invariant returned 0.
    - `exec_strategy_windows/` last-touched SHA unchanged from Task 1 baseline (D-34-B2 surgical posture verified).
    - `grep -c 'allow_connect_port.*wfp\|wfp.*allow_connect_port' crates/nono-cli/src/` returns `0` (NO WFP retrofit).
    - `nono run --allow-connect-port 443 -- echo ok` exits 0 (flag accepted; behavior is proxy-only per D-34-B2).
  </acceptance_criteria>
  <done>
    C4 chain complete; surgical posture preserved.
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
    Plan 34-02 close-gate cleared.
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
    2. `gh pr create --title "Plan 34-02 (C4): Proxy/network hardening + --allow-connect-port (v0.42–v0.45, 4 commits)"`.
  </action>
  <verify>
    <automated>git fetch origin &amp;&amp; test "$(git log origin/main..main --oneline | wc -l)" = "0"</automated>
  </verify>
  <acceptance_criteria>
    - Pushed; PR opened.
  </acceptance_criteria>
  <done>
    Plan 34-02 published.
  </done>
</task>

</tasks>

<non_goals>
**D-34-B2 surgical posture — `--allow-connect-port` is proxy-only.** No fork-side WFP wiring. Phase 09 `--allow-port` remains a parallel, independent layer.

**No `nono-proxy` Windows credential-injection rewrite touched.** Plan 34-10 (C11 manual replay) handles that surface; C4 absorbs upstream's NO_PROXY + TLS-roots fixes without overlap.

**No `*_windows.rs` touched.**

**No MSI installer integration for native TLS roots.** `cb6b199c` lands the native-TLS code path; MSI distribution scenarios use whatever TLS roots are present on the build/install host.
</non_goals>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Sandboxed agent → nono-proxy CONNECT request | `--allow-connect-port` enforces outbound TCP port allowlist at the proxy layer. |
| NO_PROXY env-var → proxy bypass decision | `ad23d794` closes a silent-bypass hole. |
| OS trust-store → package-download TLS verification | `cb6b199c` switches from rustls bundled roots to native trust-store. |

## STRIDE Threat Register

| Threat ID | Category | Component | Severity | Disposition | Mitigation |
|-----------|----------|-----------|----------|-------------|------------|
| T-34-02-01 | Tampering | D-21 Windows-only files invariant violation | **high** | mitigate (BLOCKING) | Per-commit D-34-E1 invariant. |
| T-34-02-02 | Repudiation | D-19 trailer missing | **high** | mitigate (BLOCKING) | Task 2 smoke. |
| T-34-02-03 | Elevation of Privilege | `--allow-connect-port` accidentally wired into Phase 09 WFP (D-34-B2 surgical-posture violation) | **high** | mitigate (BLOCKING) | Task 2 verifies `exec_strategy_windows/` untouched; grep enforces no WFP retrofit. |
| T-34-02-04 | Information Disclosure | NO_PROXY hole (pre-`ad23d794` behavior) allowed silent bypass; if cherry-pick is malformed, hole reopens | high | mitigate | Task 2 builds + integration tests for proxy NO_PROXY behavior pass. |
| T-34-02-05 | Tampering | Native-TLS roots include a compromised CA that was excluded from rustls bundled roots | medium | accept | OS trust-store curation is out of nono's scope; users trusting their OS implicitly accept its CA list. |
| T-34-02-06 | Denial of Service | `cb6b199c` native-TLS fails on stripped Windows installs (no system trust bundle) | low | mitigate | Fork's MSI installer ships with explicit TLS-root configuration; native-TLS path falls back gracefully. |
| T-34-02-07 | Spoofing | `--allow-connect-port` parses port numbers without bounds checking (port 0 or > 65535 accepted) | low | mitigate | clap parser uses u16 bounded type by default. Standard nono CLI validation. |
</threat_model>

<verification>
- All 8 D-34-D2 close-gates pass.
- `git log --format='%B' HEAD~4..HEAD | grep -c '^Upstream-commit: '` returns `4`.
- Per-commit D-34-E1 invariant: 0 hits.
- `exec_strategy_windows/` last-touched SHA unchanged (D-34-B2 surgical posture verified).
- `grep -c 'allow_connect_port.*wfp\|wfp.*allow_connect_port' crates/nono-cli/src/` returns `0`.
- `nono run --allow-connect-port 443 -- echo ok` exits 0 on Windows AND on Linux.
- `cargo test -p nono-proxy` exits 0 (NO_PROXY behavior verified).
</verification>

<success_criteria>
- 4 atomic commits on `main`, each with D-19 trailer.
- NO_PROXY hole closed; `--allow-connect-port` flag added (proxy-only per D-34-B2); native TLS roots used for package downloads.
- macOS fail-fast guard landed.
- D-34-B2 surgical posture preserved (NO WFP retrofit).
- All 8 D-34-D2 gates green.
- `origin/main` advanced; PR opened.
</success_criteria>

<output>
After completion, create `.planning/phases/34-upst3-upstream-v0-41-v0-52-sync-execution/34-02-SUMMARY.md`.
</output>
