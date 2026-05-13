---
slug: divergence-ledger-v052-v053
status: complete
type: audit-only
date: 2026-05-13
range: v0.52.0..v0.53.0
upstream_head_at_audit: fc5c9553b11631f8ec9157b43c3a032f1cc946a6
drift_tool_sh_sha: 0834aa664fbaf4c5e41af5debece292992211559
drift_tool_ps1_sha: 0834aa664fbaf4c5e41af5debece292992211559
drift_tool_invocation: 'make check-upstream-drift ARGS="--from v0.52.0 --to v0.53.0 --format json"'
fork_baseline: v0.52.0 (Phase 34 UPST3 sync point — 2026-05-12)
total_unique_commits: 22
---

# Upstream v0.52.0 → v0.53.0 divergence ledger

## Headline

**22 non-merge cross-platform commits across 3 minor releases (v0.52.1 → v0.53.0); ~2,611 insertions / ~487 deletions across drift-tool categories: profile=1, policy=0, package=0, proxy=8, audit=1, other=15.**

Seven themed clusters span the range. Four clusters disposition `will-sync` (carry into Phase 40 UPST4-sync execution); two `fork-preserve` (manual-replay shape per D-20, cherry-pick would collide with fork-only wiring — cluster 4 profile-save denial suppression, cluster 5 proxy TLS trust + multi-route dispatch); one `won't-sync` (cluster 3 PTY scrollback polish — fork's ConPTY attach path on Windows is structurally different per D-11).

**ZERO commits flagged `windows-touch: yes` against the D-39-C2 mechanical heuristic in the v0.52.0..v0.53.0 range** — see [§ ADR review](#adr-review) below for the empirical finding. The two Windows-touching commits surfaced in 39-CONTEXT.md preview (`5d821c12 fix(platform): correctly parse windows registry dword values` and `0748cced feat(platform): implement robust windows platform detection`) were authored 2026-05-12, AFTER the v0.53.0 release tag (commit `c4b25b82`, dated 2026-05-11). Both are reachable from `v0.54.0~5^2` and therefore land in UPST5 absorption per the D-39-D2 post-lock-upstream-commits rule + D-39-A3 strictly-silent-on-post-v0.53.0 invariant. The new `windows-touch` column on commit rows (D-39-C1) remains the structural carrier for this signal; it stays "no" for all 22 rows in this audit range.

## Reproduction

This audit is regenerable from the values in the YAML frontmatter above (D-39-A2 / D-39-E1):

```bash
git fetch upstream --tags
# Drift-tool script pinned at sha 0834aa664fbaf4c5e41af5debece292992211559 (Phase 24 ship sha; unchanged at audit time):
make check-upstream-drift ARGS="--from v0.52.0 --to v0.53.0 --format json"
# (On Windows hosts where `make` is not on PATH, the Makefile target dispatches to
#  bash scripts/check-upstream-drift.sh ... — same shell command, same JSON output.)
```

Per D-39-A2 / D-39-E1 the raw JSON output is NOT committed. The cluster tables below are the canonical artifact — the JSON is regenerable on demand from the locked invocation + the upstream HEAD sha + drift-tool script sha recorded in the frontmatter.

Per D-11 (see [Phase 24 CONTEXT.md](../24-parity-drift-prevention/24-CONTEXT.md) D-11), `*_windows.rs` and `crates/nono-cli/src/exec_strategy_windows/` are EXCLUDED from drift-tool output. The `windows-touch` column on commit rows (D-39-C1) flags upstream commits adding NEW Windows code OUTSIDE the D-11-excluded paths — D-11 is necessary but not sufficient. Fork-only Windows surface added since Phase 33 is enumerated by reference to [Phase 33 ledger § Fork-only surface area](#fork-only-surface-area) below (no new fork-only Windows surface introduced in Phases 35–36.5 per audit-walk against those phase SUMMARYs); cluster dispositions cover only the cross-platform surface the tool walks plus any windows-touch:yes additions (zero in this audit range).

**Inspection methodology** (mirrors Phase 33 D-33-A1 + D-39-C2 extension): each commit's `subject` + `categories` + `files_changed[]` length was read from the drift JSON for every row; per-commit diffs were read for the lead commit in each cluster (the one introducing the feature), any commit whose subject was ambiguous re: disposition, AND every commit flagged by the D-39-C2 mechanical windows-touch heuristic (none surfaced in this range; the heuristic set `windows-touch: yes` iff any file in `files_changed` matched `windows` substring or the pinned list `{platform.rs, registry.rs, wfp/*, win_*.rs}` OR commit subject contained `windows / wfp / registry / wsa / ntdll / kernel32` — zero hits across all 22 commits). Auditor judgment-override capability was retained but not exercised — no ambiguous `feat(platform)` cases surfaced in v0.52.0..v0.53.0.

## Cluster Summary

| # | Cluster (introduced in) | Commit count | Disposition | One-line summary |
|---|-------------------------|--------------|-------------|------------------|
| 1 | Proxy server hardening (libdbus, Node 26 NO_PROXY, warning messages) (v0.52.1) | 5 | `will-sync` | proxy/server.rs review fixes + libdbus feature-unification fix + NODE_USE_ENV_PROXY for Node 26 + accurate warning message |
| 2 | CLI --allow path validation + nono why proxy-domain awareness (v0.52.1) | 2 | `will-sync` | validate --allow paths AND persist domain allowlist in sandbox state + make `nono why --host` aware of proxy domain filtering |
| 3 | PTY scrollback + keyboard-mode resets (v0.52.1) | 3 | `won't-sync` | Unix-side scrollback preservation on PTY exit + keyboard-mode resets — fork's Windows ConPTY attach path is structurally different (D-11; same justification as Phase 33 Cluster 1) |
| 4 | Profile-save denial suppression (v0.52.2) | 2 | `fork-preserve` | suppress save-profile prompts for denied paths + review-feedback fix — manual-replay shape (D-20); composes with fork's Windows-prompt UX surface that the cherry-pick would overwrite |
| 5 | Proxy TLS trust + intercept auth + multi-route dispatch + credential matching (v0.52.2, v0.53.0) | 3 | `fork-preserve` | TLS trust + auth intercept + multi-route dispatch + credential-match deny/passthrough — manual-replay (D-20; direct follow-on to Phase 33 Cluster 11 fork-preserve disposition for `nono-proxy` Windows credential-injection surface) |
| 6 | Secret scrubbing for command arguments + scrub refactor (v0.53.0) | 2 | `will-sync` | new `scrub` module scrubbing command arguments for secrets in audit events (+ subsequent optimization refactor) — audit-correctness fix the fork's audit-event surface (Phase 23 REQ-AUD-05) consumes byte-identically |
| 7 | Sandbox/Landlock optimization + diagnostic improvements + release ride-alongs (v0.52.1, v0.52.2, v0.53.0) | 5 | `will-sync` | Landlock ABI cache via OnceLock + full failure-diagnostic preservation + 3 release commits (v0.52.1 / v0.52.2 / v0.53.0 Cargo.toml bumps) — defensive correctness fixes; release rows ride along trivially |

### Cluster: Proxy server hardening (libdbus, Node 26 NO_PROXY, warning messages) (introduced in v0.52.1)

- **Disposition:** will-sync
- **Rationale:** Five small fixes in `crates/nono-proxy/src/server.rs` and adjacent surface: (a) `abc86f6` prevents feature unification from linking libdbus in no-keyring builds — important for fork's MSI-installed Windows path where libdbus is structurally unavailable (Windows uses Windows Credential Manager via `keyring v3`, not libsecret/dbus); (b) `d57375e` sets `NODE_USE_ENV_PROXY` for Node 26 (HTTP_PROXY/HTTPS_PROXY env semantics shift in Node 26+ — composes cleanly with fork's proxy interception path); (c) `5e6e7ca` + `eedfbcd` + `be8cd00` are server.rs review fixes + accurate warning message + doc comment update — straight cherry-picks. Cluster composes cleanly with fork's existing `nono-proxy` surface and does NOT intersect the Windows credential-injection rewrite that Cluster 5 covers separately.
- **Target phase:** UPST4-sync (Phase 40)

| sha | subject | upstream-tag | categories | files-changed | windows-touch |
|-----|---------|--------------|------------|---------------|---------------|
| 5e6e7ca | Update crates/nono-proxy/src/server.rs | v0.52.1 | proxy | 1 | no |
| eedfbcd | Update crates/nono-proxy/src/server.rs | v0.52.1 | proxy | 1 | no |
| be8cd00 | fix: provide more accurate warning message + doc comment update | v0.52.1 | proxy | 1 | no |
| abc86f6 | fix: prevent feature unification from linking libdbus in no-keyring builds | v0.52.1 | other,proxy | 2 | no |
| d57375e | fix(proxy): set NODE_USE_ENV_PROXY for Node 26 | v0.52.1 | proxy | 1 | no |

### Cluster: CLI --allow path validation + nono why proxy-domain awareness (introduced in v0.52.1)

- **Disposition:** will-sync
- **Rationale:** Two CLI surface fixes the fork should pick up: (a) `f72ea31` validates `--allow` paths and persists the domain allowlist in sandbox state — a security-relevant correctness fix (the fork's `crates/nono-cli/src/sandbox_state.rs` already shapes domain-allowlist persistence cross-platform per Phase 09; this commit closes a validation gap that affects fork users on every platform identically); (b) `85f0acc` makes `nono why --host` aware of proxy domain filtering — diagnostic-correctness fix that composes with fork's `nono why` Windows surface. No D-19 risk — both touch only `crates/nono-cli/src/` cross-platform files (`cli.rs`, `sandbox_state.rs`, `why_runtime.rs`, `profile/mod.rs`, `query_ext.rs`). **Wave-hint: foundation** — `f72ea31` extends `SandboxState` shape that downstream clusters may consume; Phase 40 may sequence this early to avoid cherry-pick conflicts.
- **Target phase:** UPST4-sync (Phase 40)
- **Wave-hint:** foundation

| sha | subject | upstream-tag | categories | files-changed | windows-touch |
|-----|---------|--------------|------------|---------------|---------------|
| f72ea31 | fix(cli): validate --allow paths and persist domain allowlist in sandbox state | v0.52.1 | other | 5 | no |
| 85f0acc | fix(cli): make 'nono why --host' aware of proxy domain filtering | v0.52.1 | other | 2 | no |

### Cluster: PTY scrollback + keyboard-mode resets (introduced in v0.52.1)

- **Disposition:** won't-sync
- **Rationale:** Three Unix-side PTY polish fixes that do not flow into fork's Windows attach path: (a) `c444c7f fix(pty): stop clearing terminal scrollback on exit for normal-mode sessions` touches `crates/nono-cli/src/pty_proxy.rs` (cross-platform PTY proxy used on Linux/macOS attach paths; fork's Windows attach path lives in `pty_proxy_windows.rs` which is D-11 excluded and ConPTY-based, structurally different from upstream's portable_pty primitives); (b) `f090d81 fix: preserve two keyboard-mode resets` is paired with (a) for keyboard-mode-reset semantics on Unix PTY exit; (c) `d9dcf95 fix: documented concat! blocks instead of opaque byte blobs` is a code-clarity refactor in the same Unix-PTY surface. Same justification class as Phase 33 Cluster 1 (PTY attach/detach + signal handling, also `won't-sync`): the Unix-side PTY polish is consumed only by macOS attach in the fork (Linux is a POC); the fork's own Phase 17 live-stream attach work (v2.1) + Phase 30 ConPTY architecture investigation already satisfied the user-visible scrollback requirement on the supported Windows path. Per Phase 33 CONTEXT Specifics §5 ("upstream churn not relevant to fork").
- **Target phase:** — (n/a)

| sha | subject | upstream-tag | categories | files-changed | windows-touch |
|-----|---------|--------------|------------|---------------|---------------|
| c444c7f | fix(pty): stop clearing terminal scrollback on exit for normal-mode sessions | v0.52.1 | other | 2 | no |
| f090d81 | fix: preserve two keyboard-mode resets | v0.52.1 | other | 1 | no |
| d9dcf95 | fix: documented concat! blocks instead of opaque byte blobs | v0.52.1 | other | 1 | no |

### Cluster: Profile-save denial suppression (introduced in v0.52.2)

- **Disposition:** fork-preserve
- **Rationale:** Upstream `9b07bf7 feat(profile-save): suppress save-profile prompts for denied paths` (11 files touched) is a substantial UX rework of the profile-save flow that touches `profile_save_runtime.rs`, `terminal_approval.rs`, `policy.rs`, and several runtime call sites; `eb6cb09 fix(profile-save): address suppression review feedback` is the follow-on review fix. The fork's profile-save UX is the cross-platform layer that Phase 36 / Phase 36.5 profile-drafts surface (REQ-PORT-CLOSURE-02 + REQ-PORT-CLOSURE-03) just landed (2026-05-13). Cherry-pick risk: the upstream suppression-of-denied-paths flow may collide with fork-side `terminal_approval.rs` per-kind prompt templates (Phase 18.1 Plan 18.1-01 build_prompt_text — D-04-locked per-HandleKind template surface) or with fork's Windows prompt-suppression UX. Manual-replay shape is correct here (D-20 precedent — Phase 26 Plan 26-01 PKGS-02 + Phase 34 4 manual-replay clusters). Phase 40 plan-phase may upgrade to `will-sync` after diff inspection confirms the upstream commits compose with fork's per-kind prompt surface; conservative default applied here.
- **Target phase:** UPST4-sync (Phase 40)

| sha | subject | upstream-tag | categories | files-changed | windows-touch |
|-----|---------|--------------|------------|---------------|---------------|
| 9b07bf7 | feat(profile-save): suppress save-profile prompts for denied paths | v0.52.2 | other,profile | 11 | no |
| eb6cb09 | fix(profile-save): address suppression review feedback | v0.52.2 | other | 1 | no |

### Cluster: Proxy TLS trust + intercept auth + multi-route dispatch + credential matching (introduced in v0.52.2, v0.53.0)

- **Disposition:** fork-preserve
- **Rationale:** Direct follow-on to Phase 33 Cluster 11 (Proxy TLS interception + audit-event structured context, fork-preserve) — same fork-only `nono-proxy` Windows credential-injection surface, same D-20 manual-replay justification. (a) `8ddb143 feat: fix upstream TLS trust, intercept auth, and multi-route dispatch` (4 files: `route.rs`, `credential.rs`, `server.rs`, `tls_intercept/handle.rs`) is the substantial 2026 follow-on to upstream's v0.51 tls-interception work; cherry-pick would merge directly into fork's `nono-proxy/src/credential.rs` which was rewritten on `windows-squash` for Windows credential injection (Phase 09 + Phase 11). (b) `54c7552 fix: review comments` is the post-`8ddb143` review fix. (c) `f77e0e3 fix: absolute match / 2 matches = deny / no match = passthrough w no creds` defines credential-match semantics that the fork's Windows credential-injection path must consciously decide to adopt (the policy semantics around "no match = passthrough w no creds" intersect Windows-side credential-store fallback behavior). Manual-replay required (D-20 precedent inherited from Phase 33 Cluster 11). Phase 40 plan-phase will need to audit each upstream change against the fork's Windows credential-store path before any cherry-pick.
- **Target phase:** UPST4-sync (Phase 40)

| sha | subject | upstream-tag | categories | files-changed | windows-touch |
|-----|---------|--------------|------------|---------------|---------------|
| 8ddb143 | feat: fix upstream TLS trust, intercept auth, and multi-route dispatch. | v0.53.0 | proxy | 4 | no |
| 54c7552 | fix: review comments | v0.53.0 | proxy | 1 | no |
| f77e0e3 | fix: absolute match / 2 matches = deny / no match = passthrough w no creds | v0.53.0 | proxy | 2 | no |

### Cluster: Secret scrubbing for command arguments + scrub refactor (introduced in v0.53.0)

- **Disposition:** will-sync
- **Rationale:** New `crates/nono/src/scrub.rs` module + audit-event integration: `6472011 feat(core): scrub command arguments for secrets` (14 files including new `scrub.rs`, `lib.rs` re-export, integration into `audit_integrity.rs` + `audit_ledger.rs` + `command_runtime.rs` + audit-event emission sites) is a clean audit-correctness feature the fork's Phase 23 REQ-AUD-05 Windows AIPC ledger surface (`audit_integrity.rs` + `audit_ledger.rs`) consumes byte-identically. The subsequent optimization refactor (`78114e6 refactor(scrub): optimize and simplify scrubbing logic`) rides along. **Wave-hint: foundation for any downstream cluster that consumes `nono::scrub::*` from `lib.rs` re-exports — Phase 40 may sequence this early.** No D-19 risk — `crates/nono/src/scrub.rs` is a new cross-platform module that the fork has no analog for; cherry-pick lands cleanly without removing fork-only wiring.
- **Target phase:** UPST4-sync (Phase 40)
- **Wave-hint:** foundation

| sha | subject | upstream-tag | categories | files-changed | windows-touch |
|-----|---------|--------------|------------|---------------|---------------|
| 6472011 | feat(core): scrub command arguments for secrets | v0.53.0 | audit,other | 14 | no |
| 78114e6 | refactor(scrub): optimize and simplify scrubbing logic | v0.53.0 | other | 1 | no |

### Cluster: Sandbox/Landlock optimization + diagnostic improvements + release ride-alongs (introduced in v0.52.1, v0.52.2, v0.53.0)

- **Disposition:** will-sync
- **Rationale:** Defensive correctness fixes + release ride-alongs that compose trivially with the fork: (a) `5b61971 fix(sandbox): cache Landlock ABI detection with OnceLock` is a Linux-only optimization in `crates/nono/src/sandbox/linux.rs` that the fork's Linux POC inherits identically (same OnceLock pattern fork already uses elsewhere, e.g., `LEGACY_OVERRIDE_DENY_WARNED` in Phase 36); (b) `5a61808 fix: return full failure diagnostic` improves error-reporting at supervisor boundaries — cross-platform diagnostic correctness; (c) `21bbb82` + `e8bf014` + `c4b25b8` are the three release commits (v0.52.1 / v0.52.2 / v0.53.0 Cargo.toml version bumps) — these always ride along with the parent release cluster cherry-pick chain per Phase 33 / Phase 34 precedent. No fork-only collision risk.
- **Target phase:** UPST4-sync (Phase 40)

| sha | subject | upstream-tag | categories | files-changed | windows-touch |
|-----|---------|--------------|------------|---------------|---------------|
| 5b61971 | fix(sandbox): cache Landlock ABI detection with OnceLock | v0.53.0 | other | 1 | no |
| 5a61808 | fix: return full failure diagnostic | v0.53.0 | other | 1 | no |
| 21bbb82 | chore: release v0.52.1 | v0.52.1 | other | 1 | no |
| e8bf014 | chore: release v0.52.2 | v0.52.2 | other | 1 | no |
| c4b25b8 | chore: release v0.53.0 | v0.53.0 | other | 1 | no |

## ADR review

The Phase 33 strategic ADR (`docs/architecture/upstream-parity-strategy.md`, `Status: Accepted` 2026-05-11) chose Option A `continue`. This audit confirms compatibility:

(a) **Audit surfaced ZERO upstream Windows-code additions outside D-11-excluded paths in the v0.52.0..v0.53.0 range.** The D-39-C2 mechanical heuristic (subject keywords `windows / wfp / registry / wsa / ntdll / kernel32` + files matching pinned list `{platform.rs, registry.rs, wfp/*, win_*.rs}`) returned zero hits across all 22 commits. **Empirical finding (contradicts 39-CONTEXT.md preview):** the two Windows-touching commits surfaced in CONTEXT § Drift signal preview (`5d821c12 fix(platform): correctly parse windows registry dword values` and `0748cced feat(platform): implement robust windows platform detection`) were authored 2026-05-12 (the day after the v0.53.0 release commit `c4b25b82` dated 2026-05-11) and are reachable only from `v0.54.0~5^2` and `v0.54.0~5^2~1` respectively. Both commits touch `crates/nono-cli/src/platform.rs` (cross-platform file, NOT D-11-excluded) and therefore WOULD have flagged `windows-touch: yes` if they had landed in this audit range — but they did not. Per D-39-A1 + D-39-A3 the audit range is `v0.52.0..v0.53.0` strictly; post-v0.53.0 commits roll into UPST5 absorption (D-39-D2). The CONTEXT preview was gathered 2026-05-13 BEFORE `v0.54.0` was tagged (drift-tool fetch at the start of Plan 39-01 revealed `v0.54.0` as a `[new tag]`, dated 2026-05-13 09:52:48 +0100 — the same calendar day this audit ran) which is why the preview attributed the two commits to v0.53.0 by inspection of upstream/main rather than tag-range walk. The audit-of-record (frontmatter `upstream_head_at_audit: fc5c9553` + `range: v0.52.0..v0.53.0` + drift-tool exit 0) is reproducible against the locked input set; the preview was informational, not normative.

(b) **Phase 33 ADR Option A `continue` did not anticipate this shape explicitly.** The v0.40.1..v0.52.0 audit range (Phase 33) had ZERO upstream commits touching Windows code outside D-11-excluded paths (verified against Phase 33 [DIVERGENCE-LEDGER.md](../33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md) — no `windows-touch` column was needed at that audit time). Phase 39's v0.52.0..v0.53.0 range ALSO has ZERO such commits. The new `windows-touch` column on commit rows (D-39-C1) was added in this audit cycle as a forward-cadence structural carrier; UPST5 will be the first audit cycle where the column actually fires (the two `5d821c12` + `0748cced` commits will absorb into UPST5 with `windows-touch: yes` flags and the D-39-C3 conservative-default `fork-preserve` disposition).

(c) **`fork-preserve` default per D-39-C3 not exercised in this audit cycle.** Because no `windows-touch: yes` commits surfaced, the D-39-C3 conservative-default-to-fork-preserve invariant did not fire. The two `fork-preserve` clusters in this audit (Cluster 4 profile-save denial suppression, Cluster 5 proxy TLS trust + multi-route dispatch) carry their disposition for D-20 manual-replay reasons (cherry-pick would collide with fork-only Windows credential-injection wiring per Phase 33 Cluster 11 precedent + fork-side profile-save UX surface) — independent of the windows-touch heuristic. The D-39-C3 invariant + its companion `## ADR review` section structure remain in the ledger as scaffolding for future audit cycles (UPST5 onward).

(d) **Phase 33 ADR remains `Accepted` — no superseding ADR needed yet.** Phase 39 does not supersede the ADR. The cadence rule from `docs/architecture/upstream-parity-strategy.md` § Future audit cadence holds: per upstream release, lazily-evaluated. UPST5 is queued in `.planning/ROADMAP.md` § v2.5 backlog (per D-39-B4) as the next absorption cycle, and UPST5 will be the first audit where the v0.54.0 Windows-platform-detection commits get formal disposition.

## Fork-only surface area

Surface added since v0.40.1 with NO upstream analog. The drift tool's D-11 filter (`*_windows.rs` + `crates/nono-cli/src/exec_strategy_windows/` excluded) hides ALL of this from the audit walk. Phase 39 references Phase 33's enumeration unchanged — audit-walk against the Phase 35 / 36 / 36.5 SUMMARYs confirms no new fork-only Windows surface was introduced in those phases (Phase 35 = Windows env-filter wiring + Linux Landlock + test-harness hygiene; Phase 36 = cross-platform deprecated_schema + canonical Profile sections + override_deny rename + yaml_merge + ExecConfig surgical port; Phase 36.5 = cross-platform profile-drafts feature — none of these introduced new `*_windows.rs` or `exec_strategy_windows/` files).

See [Phase 33 ledger § Fork-only surface area](../33-windows-parity-upstream-0-52-divergence/DIVERGENCE-LEDGER.md#fork-only-surface-area) for the full enumeration: `crates/nono-shell-broker/` (Phase 31), Phase 27.1 `NONO_TEST_HOME` seam, Phase 28 Authenticode chain-walker, Phase 31 `WindowsTokenArm::BrokerLaunch` arm, Phase 32 Sigstore TUF cached-root, Phase 32 broker self-trust-anchor, plus the 8 `*_windows.rs` files surfaced by `git ls-files | grep -E '_windows\.rs$'` (verified byte-identical at Phase 39 audit time on 2026-05-13).
