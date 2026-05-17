---
slug: divergence-ledger-v053-v054
status: complete
type: audit-only
date: 2026-05-17
range: v0.53.0..v0.54.0
upstream_head_at_audit: 94fc4c6aa2f3d328c5f222c10c9c14352b179ddb
drift_tool_sh_sha: 0834aa664fbaf4c5e41af5debece292992211559
drift_tool_ps1_sha: 0834aa664fbaf4c5e41af5debece292992211559
drift_tool_invocation: 'make check-upstream-drift ARGS="--from v0.53.0 --to v0.54.0 --format json"'
fork_baseline: v0.53.0 (Phase 40 UPST4 sync point — 2026-05-14)
total_unique_commits: 18
---

# Upstream v0.53.0 → v0.54.0 divergence ledger

## Headline

**18 non-merge commits across 1 minor release (v0.54.0); ~4,064 insertions / ~1,805 deletions across drift-tool categories: profile=3, policy=2, package=5, proxy=1, audit=1, other=18.**

Seven themed clusters span the range. Four clusters disposition `will-sync` (carry into Phase 43 UPST5-sync execution); two `fork-preserve` (manual-replay per D-20 and D-42-C3 windows-touch default — Cluster 4 Windows platform detection, Cluster 5 platform-conditional profile fields); one `won't-sync` (Cluster 6 macOS lint fixes — fork's clippy ruleset diverges; absorb selectively if CI ever surfaces matching diagnostics). **Three commits flagged `windows-touch: yes` against the D-42-C2 mechanical heuristic** with judgment-override applied: `0748cced feat(platform): implement robust windows platform detection`, `5d821c12 fix(platform): correctly parse windows registry dword values`, and `ce06bd59 feat(profile): add platform-conditional profile fields` (introduces the cross-platform `platform.rs` module that 0748cced + 5d821c12 build on). **This is the first audit cycle where the `windows-touch` column actually fires** — Phase 33 had zero windows-touch:yes fires across 97 audited commits, Phase 39 had zero across 22, Phase 42 has 3 across 18. The two known fires (`5d821c12` + `0748cced`) plus the upstream-introduced `platform.rs` foundation (`ce06bd59`) are dispositioned explicitly per ROADMAP success criterion #2; see [§ ADR review](#adr-review) below for the per-cell L/M/H verdicts on Option A `continue`.

A CONTEXT-preview correction surfaced during audit-walk (Rule 1 deviation): the Phase 42 context note classified `66c69f86 fix(snapshot): validate restore targets against symlinks` and `803c6947 chore(deps): bump nix from 0.31.2 to 0.31.3` as post-v0.54.0 commits that would defer to UPST6. The drift-tool's authoritative output places both in the v0.53.0..v0.54.0 range — both are dispositioned here. Only `fc965ccc chore(deps): bump tokio` and `089cf6a0 chore(deps): bump cosign-installer` remain genuinely post-v0.54.0 and deferred to UPST6 per D-42-A4.

## Reproduction

This audit is regenerable from the values in the YAML frontmatter above (D-42-A2 / D-42-E3):

```bash
git fetch upstream --tags
# Drift-tool script pinned at sha 0834aa664fbaf4c5e41af5debece292992211559 (Phase 24 ship sha; unchanged through Phase 33 + 39 + 42):
make check-upstream-drift ARGS="--from v0.53.0 --to v0.54.0 --format json"
# (On Windows hosts where `make` is not on PATH, the Makefile target dispatches to
#  bash scripts/check-upstream-drift.sh ... — same shell command, same JSON output.)
```

Per D-42-A2 / D-42-E3 the raw JSON output is NOT committed. The cluster tables below are the canonical artifact — the JSON is regenerable on demand from the locked invocation + the upstream HEAD sha + drift-tool script sha recorded in the frontmatter.

Per D-11 (see [Phase 24 CONTEXT.md](../24-parity-drift-prevention/24-CONTEXT.md) D-11), `*_windows.rs` and `crates/nono-cli/src/exec_strategy_windows/` are EXCLUDED from drift-tool output. The `windows-touch` column on commit rows (D-42-C1) flags upstream commits adding NEW Windows code OUTSIDE the D-11-excluded paths — D-11 is necessary but not sufficient, and **Phase 42 is the first audit cycle where this insufficiency materially fires** (`0748cced` + `5d821c12` touch `crates/nono-cli/src/platform.rs` — outside D-11's exclusion; `ce06bd59` introduces that very file with 659 net additions).

**Inspection methodology** (mirrors Phase 33 + 39 + D-42-C2 extension): each commit's `subject` + `categories` + `files_changed[]` length was read from the drift JSON for every row; per-commit diffs were read for the lead commit in each cluster, any commit whose subject was ambiguous re: disposition, AND every commit flagged by the D-42-C2 mechanical windows-touch heuristic. The D-42-C2 mechanical pass set `windows-touch: yes` iff: (a) any file in `files_changed` matches `windows` substring or pinned list `{platform.rs, registry.rs, wfp/*, win_*.rs}`, OR (b) commit subject contains `windows / wfp / registry / wsa / ntdll / kernel32` keywords. Auditor judgment-override applied per cluster-lead and per ambiguous-subject commit per D-42-C2 — most notably for `8b888a1c` (Rust 2024 edition migration), where the mechanical heuristic flags `yes` because `platform.rs` is in the files_changed list, but the diff is pure cross-platform edition-migration boilerplate (use `dyn`, parens around bare trait bounds, edition-2024 closure-capture semantics) with no Windows-conditional logic — judgment-override flips to `no`. The diff inspection for `5d821c12` and `0748cced` and `ce06bd59` also surveyed fork-side analogs per D-42-C3: **fork has NO `crates/nono-cli/src/platform.rs` file** (verified via `ls`); the closest fork-side Windows surface is the scattered `*_windows.rs` files (`exec_identity_windows.rs`, `learn_windows.rs`, `pty_proxy_windows.rs`, etc.) which are D-11 excluded and serve different concerns (PTY proxy, learn mode, session commands — not platform detection).

**D-42-A4 strictly-silent-on-post-v0.54.0 invariant honored:** two known post-v0.54.0 commits (`fc965ccc chore(deps): bump tokio`, `089cf6a0 chore(deps): bump cosign-installer`) are explicitly out of scope and deferred to UPST6 per CONTEXT § Phase Boundary; this ledger does not disposition them. Note Rule 1 deviation (above): the original CONTEXT preview misclassified `66c69f86` + `803c6947` as post-v0.54.0; both are actually reachable from v0.54.0 and are dispositioned in Clusters 7 (snapshot symlink fix) and 1 (nix bump → Cluster 1's release-ride sub-cluster).

## Cluster Summary

| # | Cluster (introduced in) | Commit count | Disposition | One-line summary |
|---|-------------------------|--------------|-------------|------------------|
| 1 | Pack management (nono update + pinning/outdated + hints) (v0.54.0) | 8 | `will-sync` | new `nono update` command + `pack pinning` / `pack outdated` commands + inline pack update hints in pack_update_hint.rs; new cross-platform CLI surface |
| 2 | Rust edition 2024 + workspace dependency centralization (v0.54.0) | 1 | `will-sync` | workspace-wide edition 2024 + nix/landlock/url/getrandom centralized in workspace.dependencies; 86 files / +2,234 / -1,470; **foundation candidate** |
| 3 | Release v0.54.0 + nix bump (v0.54.0) | 2 | `will-sync` | release commit (Cargo.toml version bump per Phase 34/40 release-ride convention) + nix 0.31.2 → 0.31.3 dependency bump (cross-platform dep, no Windows-only effect) |
| 4 | Windows platform detection (v0.54.0) | 2 | `fork-preserve` | new robust Windows platform-detection module via registry queries + REG_DWORD parse fix — windows-touch:yes; D-42-C3 conservative default applies; fork-side `platform.rs` is empty so will-sync upgrade IS available, but cluster stays fork-preserve to keep dispositioning conservative for the first windows-touch:yes cycle (manual-replay rationale below) |
| 5 | Platform-conditional profile fields (v0.54.0) | 1 | `fork-preserve` | introduces `crates/nono-cli/src/platform.rs` (659 lines) + `when` predicates on profile fields + wiring directives; windows-touch:yes (creates the file 0748cced/5d821c12 build on); D-42-C3 default applies + may intersect fork's Phase 22 `unsafe_macos_seatbelt_rules` + Phase 36 canonical-sections work |
| 6 | macOS lint fixes (v0.54.0) | 3 | `won't-sync` | three small `cargo clippy --target=apple-darwin` lint fixes (macOS-only warnings); fork's CI runs Linux + macOS Clippy on every PR per Phase 41 close-gate; if any of these affect fork-shared files identically, fork's own clippy run would catch the same diagnostic — fork has not surfaced these warnings so the clippy ruleset diverges; absorb only if fork's CI ever surfaces the same warnings |
| 7 | Snapshot restore symlink validation (v0.54.0) | 1 | `will-sync` | security fix introducing pre-flight `validate_restore_target` defending the restore mechanism against symlink-redirect race conditions; cross-platform; the exact security-fix flow-in scenario the ADR's security-posture cell argued for |

### Cluster: Pack management (nono update + pinning/outdated + hints) (introduced in v0.54.0)

- **Disposition:** will-sync
- **Rationale:** Eight commits introduce a substantial new pack-management CLI surface: `nono update` for refreshing installed packs (`a5985edd`), `package pinning` and `package outdated` subcommands (`64d9f283`, `5098fc10`), inline pack update hints with synchronous refresh-on-first-run + unparsable-version-treated-as-older + documentation (`42601ed7`, `98c18f1f`, `18b03fa6`), and CLI line-break / formatting / error-handling polish (`317c97b7`, `be23d6df`). All eight touch only cross-platform `crates/nono-cli/src/` files (`pack_update_hint.rs`, `package.rs`, `package_cmd.rs`, `registry_client.rs`, `app_runtime.rs`, `cli.rs`, `cli_bootstrap.rs`, `main.rs`, `sandbox_prepare.rs`) — no `_windows.rs` or platform.rs intersection. New CLI surface composes additively with fork's existing `nono package` command surface; no D-19 risk. Phase 43 should sequence this cluster after Cluster 2 (Rust 2024) because edition-migration touches `package_cmd.rs` and `main.rs` (workspace-wide).
- **Target phase:** UPST5-sync (Phase 43)

| sha | subject | upstream-tag | categories | files-changed | windows-touch |
|-----|---------|--------------|------------|---------------|---------------|
| 42601ed | fix(pack-update-hint): treat unparsable installed as older in update check | v0.54.0 | other | 1 | no |
| 98c18f1 | feat(pack-hints): document inline pack update hints | v0.54.0 | other | 1 | no |
| 18b03fa | feat(pack_update_hint): refresh hints synchronously on first run | v0.54.0 | other | 1 | no |
| 317c97b | style(cli): adjust line breaks and module order | v0.54.0 | other | 2 | no |
| 5098fc1 | feat(packs): add pinning, outdated, and clarify publishing versioning | v0.54.0 | package,other | 3 | no |
| be23d6d | style(cli): improve formatting and simplify error handling | v0.54.0 | package,other | 2 | no |
| a5985ed | feat(cli): implement `nono update` command | v0.54.0 | package,other | 2 | no |
| 64d9f28 | feat(package): add package pinning and outdated commands | v0.54.0 | package,other | 6 | no |

### Cluster: Rust edition 2024 + workspace dependency centralization (introduced in v0.54.0)

- **Disposition:** will-sync
- **Rationale:** Single commit (`8b888a1c`) is the largest in the audit by far: 86 files touched, +2,234 / -1,470. Promotes `nix`, `landlock`, `url`, `getrandom` to `[workspace.dependencies]`; switches member crates to workspace refs for `toml`, `walkdir`, `tempfile`, `serde` (build-dep), `serde_json` (build-dep), `url`; migrates to Rust edition 2024 with associated source-level changes (use `dyn`, parens around bare trait bounds, edition-2024 closure-capture semantics in every callsite). The D-42-C2 mechanical heuristic flags `windows-touch: yes` because `crates/nono-cli/src/platform.rs` appears in `files_changed` — but the diff in that file is pure cross-platform edition-migration boilerplate (100 lines context-shift, no Windows-conditional logic added/changed). **Judgment-override applied: `windows-touch: no`** — this is a workspace-wide edition migration that incidentally touches the new platform.rs file (introduced by ce06bd59 earlier in the v0.54.0 branch sequence); it is not Windows-specific work. Phase 43 should sequence this cluster FIRST (`wave-hint: foundation`) — every downstream cluster's cherry-pick will rebase cleanly only on top of the edition-2024 migration. Fork is currently on edition 2021 per `Cargo.toml`; absorbing this commit upgrades fork to edition 2024 workspace-wide. **MSRV check required during Phase 43:** edition 2024 requires Rust 1.85+ (stabilized 2025-02-20); fork's current MSRV is 1.77 (per CLAUDE.md § Runtime). Phase 43 plan-phase must decide: (a) bump MSRV to 1.85+ (likely correct — windows-sys 0.59 already requires recent rustc) or (b) defer this cluster and pin fork at edition 2021 (would block downstream cherry-picks and accumulate divergence — not recommended).
- **Target phase:** UPST5-sync (Phase 43)
- **Wave-hint:** foundation

| sha | subject | upstream-tag | categories | files-changed | windows-touch |
|-----|---------|--------------|------------|---------------|---------------|
| 8b888a1 | feat: upgrade to Rust edition 2024, centralize workspace dependencies | v0.54.0 | other,profile,policy,proxy,audit | 86 | no |

### Cluster: Release v0.54.0 + nix bump (introduced in v0.54.0)

- **Disposition:** will-sync
- **Rationale:** Two small commits that ride along the v0.54.0 release: (a) `6b00932f chore: release v0.54.0` is the upstream Cargo.toml version bump from 0.53.0 → 0.54.0. Per Phase 34 + Phase 40 release-ride convention (precedent commit `64b231a7`): fork DROPS upstream's Cargo.toml + Cargo.lock version bumps and absorbs only CHANGELOG.md entries (fork tracks its own version separately at 0.53.0 currently; Phase 43 release-ride for this commit absorbs only CHANGELOG). (b) `803c6947 chore(deps): bump nix from 0.31.2 to 0.31.3` is a dependabot bump of the `nix` crate (used by fork's `crates/nono/` + `crates/nono-cli/` for Unix-side syscalls); cross-platform dependency bump with no Windows-only effect. Note: CONTEXT preview classified `803c6947` as post-v0.54.0 → defer to UPST6, but drift-tool authoritative output places it reachable from `v0.54.0~3` — in scope (Rule 1 deviation, documented in Headline). Phase 43 absorbs this as a straight cherry-pick of the dep bump.
- **Target phase:** UPST5-sync (Phase 43)

| sha | subject | upstream-tag | categories | files-changed | windows-touch |
|-----|---------|--------------|------------|---------------|---------------|
| 6b00932 | chore: release v0.54.0 | v0.54.0 | other | 1 | no |
| 803c694 | chore(deps): bump nix from 0.31.2 to 0.31.3 | v0.54.0 | other | 1 | no |

### Cluster: Windows platform detection (introduced in v0.54.0)

- **Disposition:** fork-preserve
- **Rationale:** Two commits that adopt Windows registry parsing for platform detection on top of the new `platform.rs` introduced by Cluster 5 (`ce06bd59`): (a) `0748cced feat(platform): implement robust windows platform detection` queries the Windows registry for product name + version + edition (~66 lines net additions to `platform.rs`, plus 67 lines on `profile/mod.rs` for `when` predicate deserialization and 4 lines on `wiring.rs` for `WiringDirective::Skipped` serialization skip); (b) `5d821c12 fix(platform): correctly parse windows registry dword values` is the fix-on-top: identifies REG_DWORD values during Windows registry parsing, converts hex-prefixed values (`0x123`) to decimal string (`"291"`), replaces `unwrap_or_default()` with `map_or("", |part| part)` to avoid panic on malformed version strings, and adds a unit test (~26 lines net to `platform.rs`). **Both are `windows-touch: yes` per D-42-C1 / D-42-C2** — both touch `crates/nono-cli/src/platform.rs` AND both subjects contain `windows` + `registry` keywords. **Fork-side analog check (D-42-C3):** the fork has NO `crates/nono-cli/src/platform.rs` file (verified via `ls`); however, fork-side Windows-detection seams exist scattered across `crates/nono-cli/src/exec_strategy_windows/` (D-11 excluded) for PTY proxy, learn mode, session commands. Per D-42-C3 the "empty fork-side ⇒ will-sync upgrade IS available" exception applies on file-existence grounds — fork could absorb both commits as a straight cherry-pick of the new module. **However, D-42-C3 conservative default is preserved here for two reasons:** (1) the upstream Windows platform-detection module would land in the same workspace as fork's Windows-specific seams in `exec_strategy_windows/`; absorbing it cleanly requires confirming no name/import collisions with fork's broker-process Phase 31 work (`crates/nono-shell-broker/`) or Phase 35/36 supervisor work; (2) this is the first windows-touch:yes audit cycle and the precedent for D-42-C3 application should be conservative — Phase 43 plan-phase can upgrade to `will-sync` after diff inspection confirms the upstream module composes cleanly with fork's Windows-supervisor seams. Phase 43 plan-phase MUST honor either disposition explicitly without re-relitigating the call per ROADMAP success criterion #2. Manual-replay rationale (D-20) if disposition stays fork-preserve: replay the *intent* (Windows registry-based platform detection) without the *form* (a new module that may collide with broker dispatch's Windows-token-arm decision tree).
- **Target phase:** UPST5-sync (Phase 43)
- **Wave-hint:** depends-on cluster-5 disposition (the two commits build on `ce06bd59`'s `platform.rs` foundation; if Cluster 5 is fork-preserve, this cluster is structurally fork-preserve too)

| sha | subject | upstream-tag | categories | files-changed | windows-touch |
|-----|---------|--------------|------------|---------------|---------------|
| 0748cce | feat(platform): implement robust windows platform detection | v0.54.0 | other,profile | 4 | yes |
| 5d821c1 | fix(platform): correctly parse windows registry dword values | v0.54.0 | other | 1 | yes |

### Cluster: Platform-conditional profile fields (introduced in v0.54.0)

- **Disposition:** fork-preserve
- **Rationale:** Single commit (`ce06bd59`) introduces the cross-platform `platform.rs` module that Cluster 4 builds on, plus a substantial `when` predicate feature on profile field deserialization: (a) NEW `crates/nono-cli/src/platform.rs` (659 lines — OS detection, distro detection, version detection, both Unix `/etc/os-release` parsing AND Windows registry seam-ready); (b) profile/mod.rs gains 217 lines for `WhenPredicate` deserialization (skips non-matching entries on conditional `paths` / `names` / `origins` / `groups` / `env_credentials`); (c) wiring.rs gains 126 lines for `WiringDirective` conditional evaluation; (d) policy.rs gains 28 lines for conditional inclusion in built-in profiles; (e) profile JSON schema gains 99 lines for `WhenPredicate` definition; (f) package_cmd.rs + main.rs + package-publishing.mdx + profile-authoring-guide.md round out the surface; (g) packages using `when` predicates must set `min_nono_version` to guarantee compatibility. **`windows-touch: yes` per D-42-C1/C2 (creates `platform.rs` which is on the pinned list).** **Fork-side analog check (D-42-C3):** fork has NO `platform.rs` AND fork's profile-deserialization surface is the cross-platform layer that Phase 36 + Phase 36.5 profile-drafts (REQ-PORT-CLOSURE-02 + REQ-PORT-CLOSURE-03) rebuilt as canonical-sections (`CommandsConfig`, `FilesystemConfig.deny/bypass_protection`, `LegacyPolicyPatch`, `DeprecationCounter`). Phase 36's canonical sections are byte-identical to upstream's pre-`when` shape; absorbing `when` predicates would extend (not replace) the canonical-section shape. **Cherry-pick risk: the upstream `WhenPredicate` deserialization touches `profile/mod.rs::From<ProfileDeserialize> for Profile` which Phase 36-01b extended exhaustively for `CommandsConfig`** — replay risk is moderate. Manual-replay shape is correct here (D-20 precedent: Phase 26 Plan 26-01 PKGS-02; Phase 34 4 manual-replay clusters; Phase 40 Plan 40-05 FP-PROFILE-SAVE). Phase 43 plan-phase reads `crates/nono-cli/src/profile/mod.rs` per-commit diff against `ce06bd59` to confirm no exhaustive-match collisions with Phase 36-01b's `From` impl, then decides cherry-pick (`will-sync`) vs replay-of-intent (`fork-preserve`). Conservative default applied here. Cluster 4 (Windows platform detection) depends on this cluster's disposition outcome.
- **Target phase:** UPST5-sync (Phase 43)

| sha | subject | upstream-tag | categories | files-changed | windows-touch |
|-----|---------|--------------|------------|---------------|---------------|
| ce06bd5 | feat(profile): add platform-conditional profile fields | v0.54.0 | profile,policy,package | 6 | yes |

### Cluster: macOS lint fixes (introduced in v0.54.0)

- **Disposition:** won't-sync
- **Rationale:** Three small commits each titled exactly `fix: macos lint`: (a) `548bb80` touches 5 files (`exec_strategy.rs`, `instruction_deny.rs`, `learn.rs`, `sandbox_log.rs`, `sandbox_prepare.rs`); (b) `021074c9` touches 2 files (`setup.rs`, `keystore.rs`); (c) `ff2d8b84` touches 1 file (`sandbox/macos.rs`). Each closes a `cargo clippy --target=apple-darwin` warning that upstream's clippy ruleset surfaced. **Fork-shared file overlap (significant — judgment required):** every one of these files exists in the fork. **Why won't-sync rather than will-sync:** fork's CI runs `cargo clippy --workspace -- -D warnings` on Linux + macOS on every PR per Phase 41 close-gate (REQ-CI-01 + REQ-CI-02 closed); after the Phase 41 baseline-reset (`13cc0628`), all fork's clippy lanes are green. The three macOS lint fixes therefore close warnings that **upstream's clippy ruleset surfaces but fork's does not** — upstream may have a stricter lint set or have changed its rustc/clippy version between v0.53 → v0.54. Absorbing these commits is structurally a no-op for fork (fork is already green). Phase 43 plan-phase may upgrade individual commits to `will-sync` if a specific diagnostic surfaces in fork's CI between Phase 42 audit close and Phase 43 sync execution — in that case, cherry-pick only the relevant subset, NOT the whole cluster. Default action: skip the cluster; document the divergence as intentional ("fork's clippy ruleset diverges from upstream's at v0.54.0; absorb selectively if fork CI surfaces matching diagnostics").
- **Target phase:** — (n/a)

| sha | subject | upstream-tag | categories | files-changed | windows-touch |
|-----|---------|--------------|------------|---------------|---------------|
| 548bb80 | fix: macos lint | v0.54.0 | other | 5 | no |
| 021074c | fix: macos lint | v0.54.0 | other | 2 | no |
| ff2d8b8 | fix: macos lint | v0.54.0 | other | 1 | no |

### Cluster: Snapshot restore symlink validation (introduced in v0.54.0)

- **Disposition:** will-sync
- **Rationale:** Single commit `66c69f86 fix(snapshot): validate restore targets against symlinks` — a security-flavored fix that introduces a pre-flight `validate_restore_target` step in `restore_to` to defend against the symlink-redirect race condition: an attacker creating a symlink between snapshot-taken and restore-invoked could redirect the restore write to a location outside the tracked directory, enabling data corruption or trust-boundary escape. Touches only `crates/nono/src/undo/snapshot.rs` (cross-platform — fork's snapshot system is byte-identical to upstream's per Phase 33 fork-only-surface enumeration: the undo module is upstream-owned, fork adds no Windows-specific snapshot logic). **`windows-touch: no`** — no platform-conditional code; the fix applies identically on Linux/macOS/Windows because `std::os::unix::fs::symlink_metadata` is the operative check (Unix path) and Windows uses `std::fs::symlink_metadata` cross-platform. **Note: CONTEXT preview classified this as post-v0.54.0 → defer to UPST6** (the assumption was that it landed in upstream after the v0.54.0 tag); drift-tool authoritative output places it reachable from `v0.54.0~3^2` — in scope (Rule 1 deviation, documented in Headline). Phase 43 absorbs this as a straight cherry-pick; the security flavor argues for sequencing this cluster early in the wave structure to close the symlink-race window in the fork too.
- **Target phase:** UPST5-sync (Phase 43)

| sha | subject | upstream-tag | categories | files-changed | windows-touch |
|-----|---------|--------------|------------|---------------|---------------|
| 66c69f8 | fix(snapshot): validate restore targets against symlinks | v0.54.0 | other | 1 | no |

## ADR review

The Phase 33 strategic ADR (`docs/architecture/upstream-parity-strategy.md`, `Status: Accepted` 2026-05-11, re-confirmed at v2.4 close per D-39-C4) chose Option A `continue`. **Phase 42 is the first audit cycle where empirical `windows-touch: yes` evidence is available** (Phase 33's v0.40.1..v0.52.0 range and Phase 39's v0.52.0..v0.53.0 range had ZERO windows-touch:yes commits). Per D-42-C4 upgrade, this section ships explicit per-cell L/M/H verdicts for the 5 dimensions enumerated in the Phase 33 ADR Decision Table.

### Per-cell L/M/H verdict — Option A `continue` at v0.53.0..v0.54.0

| Dimension | Verdict | Rationale (empirical evidence from this audit cycle) |
|-----------|---------|------------------------------------------------------|
| security posture | High | Windows-touching upstream commits (5d821c12 + 0748cced + ce06bd59) surfaced cleanly via the audit signal — D-11 path filter caught zero Windows code, but the windows-touch column (D-42-C1) caught all 3 outside-D-11 commits with the mechanical heuristic. The conservative D-42-C3 fork-preserve default keeps the D-19 byte-identity invariant intact for the first windows-touch:yes cycle; Phase 43's plan-phase has full discretion to upgrade to will-sync after fork-side analog inspection. Upstream's snapshot symlink validation (`66c69f86`) flows into fork via Cluster 7 will-sync — exactly the security-fix flow-in scenario that the ADR's security-posture Decision Table cell argued for. |
| windows parity | High | Single-CLI-surface preservation across Linux/macOS/Windows is structurally intact: the 3 windows-touch:yes commits are dispositioned in-fork (Cluster 4 + Cluster 5, both fork-preserve with explicit Phase 43 plan-phase upgrade pathway). The fork-side analog check confirmed fork has NO `platform.rs` — so upstream's new module would land additively. The ADR's user-clarity High verdict ("one nono binary, one docs URL") is preserved: Phase 43 absorbs the platform-detection feature into the same workspace where fork's Windows-specific seams already live, rather than splitting into a separate repo. |
| maintenance cost | Medium | 18 commits / 6 clusters absorbed in one audit cycle is sustainable (vs Phase 33's 97 commits / 12 clusters and Phase 39's 22 commits / 7 clusters). The 2 fork-preserve clusters (Cluster 4 + Cluster 5) represent the first windows-touch:yes manual-replay labor in fork history; if Phase 43 confirms the upgrade-to-will-sync pathway works for the platform-detection feature, the future maintenance cost stays Medium. If Phase 43 surfaces unavoidable manual-replay conflicts (e.g., upstream `WhenPredicate` collides with Phase 36-01b's `From<ProfileDeserialize>` exhaustive match), maintenance cost shifts toward High for the platform-detection-feature cluster specifically — but this is a Phase 43 plan-phase decision, not a Phase 42 audit conclusion. Cluster 2 (Rust 2024 edition) is the largest single commit at +2,234 / -1,470 / 86 files; the foundation-cluster wave-hint should keep cherry-pick conflicts contained to a single sequencing decision. |
| divergence risk | Medium | At v0.53.0..v0.54.0 the per-cycle commit count is small (~18 vs Phase 33's 97); cadence rule firing per upstream release (D-42-E8) means accumulated drift stays bounded. The first windows-touch:yes appearance (3 commits) is the divergence-risk evidence: if future cycles continue at this rate (~2-3 windows-touch:yes commits per minor release), divergence risk stays Medium because the conservative D-42-C3 default plus explicit Phase 43 fork-side analog check keeps the divergence-vs-cherry-pick trade-off bounded. If future cycles surge to 10+ windows-touch:yes commits per release, divergence risk would shift toward High and the ADR cadence-rule warning fires (per § Verdict outcome (c) below). The Rust 2024 edition migration (Cluster 2) is the largest source of divergence pressure this cycle: deferring it indefinitely accumulates substantial workspace drift; absorbing it requires an MSRV bump (1.77 → 1.85+). |
| contributor velocity | Medium | Phase 42 sized at ~1 week (1 plan, ~18 commits) — bounded; aligns with the ADR's Decision-Table Med verdict for per-release drift-audit + cherry-pick labor. The Phase 41 close-gate baseline (CI SHA `13cc0628` with all 5 Windows CI lanes green) means Phase 43's baseline-aware CI gate is a real regression detector, not baseline-drift noise — drift-audit + cherry-pick gate review burden is contained. The first windows-touch:yes cycle adds a slight per-cycle burden (Phase 43 must do fork-side analog inspection on 2 fork-preserve clusters) but this is precisely the labor the ADR allocated when scoring contributor-velocity Med. Future cycles where the windows-touch:yes count stays at ~2-3 keep velocity Medium; growth toward 10+ would shift to Low. |

### Verdict outcome

**(a) Confirm Option A `continue`.** Per-cell aggregate shape: (H, H, M, M, M) — 2 High / 3 Medium / 0 Low. This dominates Option B's reference shape (1 High / 0 Med / 4 Low) and Option C's (1 High / 2 Med / 2 Low) without invoking the D-33-C3 tiebreaker. The aggregate is one step LESS dominant than Phase 33's Wave 1 reference shape (3 High / 2 Med / 0 Low) — the Med shift on `security posture` from Phase 33's `High` to Phase 42's `High` is unchanged (security posture stays High because the windows-touch column actually surfaced the relevant commits AND upstream's snapshot symlink fix flowed in via Cluster 7); the Med drift is on `maintenance cost` (Phase 33 High → Phase 42 Medium, reflecting the first manual-replay-windows-touch-yes labor) and `divergence risk` (Phase 33 Med → Phase 42 Med, unchanged but now with empirical evidence). The Phase 33 ADR `Status: Accepted` remains in force; Phase 42 does NOT supersede. Phase 43 plan-phase MAY produce a follow-on ADR amendment if Cluster 4 + Cluster 5 manual-replay labor surfaces a structural pattern worth codifying (e.g., "windows-touch:yes platform-detection commits default to D-20 manual-replay until fork has its own platform.rs"); this is plan-phase discretion, not Phase 42 verdict.

Per the Phase 33 ADR § Future audit cadence rule (D-42-E8): "per upstream release, lazily-evaluated" — UPST6 fires when v0.55.0+ ships (already happened — `v0.55.0` tag fetched 2026-05-17 during Phase 42 audit-open's `git fetch upstream --tags`; UPST6 cadence trigger is met) or maintainer decides accumulated cherry-pick labor warrants firing. UPST6 stub queued in ROADMAP per D-42-B4.

## Empirical cross-check

Per D-42-E1, the audit walk spot-checks ≥3 fork-shared files for any upstream path the drift tool missed (Phase 39 empirical-cross-check pattern). Phase 42 preferentially samples Phase-41-touched files per D-42-E2 since those are the files most likely to have drifted from upstream in ways the drift tool's mechanical path filter (D-11) may not catch.

Methodology: for each sampled file, run `git log v0.53.0..v0.54.0 -- <file>` against `upstream/main` and confirm the drift tool's commit list covers every upstream commit touching that file.

| # | Sampled file | Subsystem | Phase-41 nexus | Upstream commits in range | Drift-tool covered | Finding |
|---|--------------|-----------|----------------|---------------------------|--------------------|---------|
| 1 | crates/nono-cli/src/exec_strategy.rs | nono-cli | Plan 41-01 HandleTarget API migration at 14 sites | 2 (`548bb800`, `8b888a1c`) | yes (both in drift JSON) | confirmed — drift tool covered every upstream commit touching this file |
| 2 | crates/nono/src/keystore.rs | nono (library) | Plan 41-06/07 broker hygiene (CR-A regression at v0.42.0 line ~942 fixed at commit `4665ae75`) | 2 (`021074c9`, `8b888a1c`) | yes (both in drift JSON) | confirmed — drift tool covered every upstream commit touching this file |
| 3 | crates/nono-cli/src/policy.rs | nono-cli | Plan 41-09 wire profile_runtime to canonical validate_env_var_patterns | 2 (`8b888a1c`, `ce06bd59`) | yes (both in drift JSON) | confirmed — drift tool covered every upstream commit touching this file |
| 4 | crates/nono-cli/src/cli.rs | nono-cli | Plan 41-09 mirror env_var pattern fix + interactive_shell field addition | 3 (`a5985edd`, `64d9f283`, `8b888a1c`) | yes (all 3 in drift JSON) | confirmed — drift tool covered every upstream commit touching this file |

**Findings summary:** All 4 sampled files PASS; drift tool's commit list is complete against the v0.53.0..v0.54.0 fork-shared surface for the sampled subsystems. No drift-tool blind spots surfaced; no D-42-D3 quick-task spawn required. The empirical cross-check confirms the D-11 path filter remains necessary-but-not-sufficient — every upstream commit touching the sampled cross-platform files appears in the drift JSON, and the new `windows-touch` column (D-42-C1) correctly flags the 3 commits outside D-11's exclusion that touch the new `platform.rs` (which IS in drift JSON because `platform.rs` is not D-11-excluded).

## Fork-only surface area

Surface added since v0.40.1 with NO upstream analog. The drift tool's D-11 filter (`*_windows.rs` + `crates/nono-cli/src/exec_strategy_windows/` excluded) hides ALL of this from the audit walk. Phase 42 references Phase 33's enumeration unchanged — Phase 41 introduced no new fork-only Windows surface (Plan 41-01 was a cross-platform API migration touching `exec_strategy.rs` at 14 sites with no new `_windows.rs` files; Plans 41-06/07 hardened existing broker CR paths in `crates/nono-shell-broker/` and `bindings/c/` without adding new files; Plans 41-08/09/10 closed CI gaps via cross-platform code changes plus template files in `.planning/templates/`).

See [Phase 33 ledger § Fork-only surface area](../33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md#fork-only-surface-area) for the full 6-seam enumeration: `crates/nono-shell-broker/` (Phase 31), NONO_TEST_HOME (Phase 27.1), Authenticode chain-walker (Phase 28), `WindowsTokenArm::BrokerLaunch` (Phase 31), Sigstore TUF cached-root (Phase 32), broker self-trust-anchor (Phase 32), plus the 8 `*_windows.rs` files (`exec_identity_windows.rs`, `learn_windows.rs`, `open_url_runtime_windows.rs`, `pty_proxy_windows.rs`, `session_commands_windows.rs`, `trust_intercept_windows.rs`, `crates/nono/src/supervisor/socket_windows.rs`, plus the Windows-only test `crates/nono-cli/tests/exec_identity_windows.rs`).
