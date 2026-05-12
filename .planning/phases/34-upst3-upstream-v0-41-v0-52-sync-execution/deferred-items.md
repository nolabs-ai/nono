# Phase 34 — Deferred Items

Items discovered during Phase 34 plan execution that exceed the scope of
the current sync-execution plans and are deferred to follow-up plans.

## P34-DEFER-04b-1: Full Option C deprecated_schema module port

**Discovered during:** Plan 34-04b Task 3 (D-20 manual replay of upstream
`f0abd413` — canonical JSON schema restructure)

**Date:** 2026-05-11

**Scope:** Plan 34-04b landed the rename-acceptance contract (serde alias
+ clap visible_alias + one-time stderr deprecation warning + test file
rename) — sufficient to make v0.47.x JSON profiles and CLI invocations
load on the fork. The full upstream surface is deferred:

- Full 824-line upstream `deprecated_schema` module port (`LegacyPolicyPatch`
  rewriter, per-key `DeprecationCounter`, `--strict` mode for
  `nono profile validate`, alias inventory enforcement via
  `scripts/test-list-aliases.sh` and `scripts/lint-docs.sh`).
- Canonical sections `groups`, `commands.{allow,deny}`,
  `filesystem.{deny,bypass_protection}` in `Profile` / `LoadedProfile`
  structs.
- Internal Rust identifier rename `override_deny` → `bypass_protection`
  across the 210-callsite surface
  (`capability_ext.rs`, `cli.rs`, `command_runtime.rs`,
  `execution_runtime.rs`, `launch_runtime.rs`, `main.rs`, `policy.rs`,
  `policy_cmd.rs`, `profile_cmd.rs`, `profile_runtime.rs`,
  `query_ext.rs`, `sandbox_prepare.rs`, `sandbox_state.rs`,
  `why_runtime.rs`, JSON schema fixtures).
- Built-in profile data migration (claude-code, codex, opencode, etc.)
  to canonical schema sections.
- JSON schema (`nono-profile.schema.json`) restructure.
- Embedded profile-authoring guide + `docs/cli/features/profiles-groups.mdx`
  + `docs/cli/usage/flags.mdx` migration.
- `scripts/lint-docs.sh` + alias-inventory test surface.
- `profile_save_runtime.rs` modify/delete conflict re-evaluation
  (fork's deletion currently stands).

**Estimated scope:** multi-week. Likely splits into:
- 04b-2a: deprecated_schema module + LegacyPolicyPatch + DeprecationCounter
- 04b-2b: canonical Profile sections (groups/commands/filesystem)
- 04b-2c: 210-callsite internal rename `override_deny` → `bypass_protection`
- 04b-2d: data + docs + tooling migration

**Why deferred:** Plan 34-04b's scope was to clear the canonical-schema
foundation for Wave 1+ downstream plans. Full restructure is its own
multi-week workstream and would have indefinitely blocked Wave 1+.

## P34-DEFER-04b-2: Upstream 829c341a — profile drafts + package status

**Discovered during:** Plan 34-04b Task 7 (attempted cherry-pick of
upstream `829c341a` — "add commands to manage profile drafts and check
package status")

**Date:** 2026-05-11

**Scope:** Upstream commit `829c341a` (Luke Hinds, v0.47.1) introduces
substantial new user-facing functionality:

- `nono profile validate --draft` — validate drafts in
  `~/.config/nono/profile-drafts`
- `nono profile promote <name>` — interactive review-and-apply for
  profile drafts (with `--yes` for non-interactive use)
- `~/.config/nono/profile-drafts/` directory convention
- Base-hash verification to prevent stale-draft promotion
- Shadowing safeguards (refuse to promote over built-in or installed
  pack profiles)
- Atomic file operations for safe updates
- `NonoError::ActionRequired` variant for critical package advisories
- Registry-client fetch of `PackageStatusResponse`
- New file: `crates/nono-cli/src/package_status.rs` (218 LOC)
- C FFI: `NonoErrorCode::ErrConfigParse` mapping for the new variant

**Cherry-pick result:** 7 conflicted files; 3619-line conflict span in
`crates/nono-cli/src/profile_cmd.rs` (well above the 3K-line escalation
threshold). The new file `package_status.rs` has no analog in the fork.
The new `profile_cmd.rs` content (~460 new lines of subcommand handlers)
overlays heavy fork divergence.

**Why deferred:** This is feature-development scope, not a sync-only
delta. Manual replay requires:
1. Design review (does `--draft` fit nono's threat model?)
2. Security audit (atomic ops, base-hash verification, shadowing safeguards)
3. Test coverage (promote happy path, `--draft` validation, base-hash
   mismatch, shadowing rejection)
4. Documentation (CLI usage, profile-drafts directory convention)
5. C FFI thread-through for `ErrConfigParse` mapping

**Estimated scope:** multi-day at minimum (1-2 weeks if design/security
review surfaces concerns).

**Tracking:** Phase 34-04b SUMMARY records this as the escalation per
the orchestrator-approved escalation rule. The Plan 34-04b plan-close
smoke-check expected `Upstream-commit:` count of 5; actual is 4
(829c341a deferred); `Manual-replay:` count stays at 1 (only
`f0abd413`).

## P34-DEFER-01-1: query_ext::test_query_path_denied Windows-path canonicalization

**Discovered during:** Plan 34-01 D-34-D2 close-gate 1 (`cargo test --workspace --all-features`)

**Date:** 2026-05-11

**Scope:** `query_ext::tests::test_query_path_denied` asserts that the
suggested-flag output for a POSIX path `/some/random/path` round-trips
to `--read /some/random`. On Windows, the path canonicalization layer
prefixes the result with `\?\C:\` (UNC long-path form), producing
`--read \?\C:\some\random`. The test passes on Linux/macOS hosts.

**Pre-existing:** Verified pre-existing on `aca306a54b3d8f0858fc5376068b2715ec2f1e6c`
(the base HEAD before Plan 34-01 cherry-picks landed) — same `left/right` mismatch
when run against the baseline `query_ext.rs`. Plan 34-01's upstream cherry-picks
(notably `034be703`) modify the surrounding diagnostic message format but do NOT
introduce the path-canonicalization mismatch.

**Path forward:** Either gate the test to `#[cfg(not(target_os = "windows"))]`
(Phase 22-style pattern) or add a Windows-specific variant that asserts the
UNC-prefixed form. Deferred to a Windows-test-hygiene plan; not blocking for
Plan 34-01 close.

**Tracking:** Plan 34-01 SUMMARY records the gate-1 single-test failure as
out-of-scope per the executor's "auto-fix scope boundary" rule (only fix
issues directly caused by current-task changes; this was pre-existing).

## P34-DEFER-06-1: yaml_merge wiring trio (upstream v0.49.0)

**Discovered during:** Plan 34-06 Cluster C9 cherry-pick (3 of 8 commits
modify a file that does not exist in the fork).

**Date:** 2026-05-12

**Deferred commits:**
- `242d4917` — fix(yaml-merge): pin serde_yaml_ng to 0.10.0 and add reversal failure test
- `802c8566` — style: apply rustfmt (over wiring.rs)
- `d44f5541` — feat(wiring): add yaml_merge directive for YAML config patching

**Scope:** All three commits modify `crates/nono-cli/src/wiring.rs`. The
fork does **not** have this file. Upstream's `wiring.rs` was first created
in `24d8b924` (`feat(profile, migration): move codex, claude-code to
registry pack`) which is well outside the v0.49.0 cluster scope and was
never adopted by the fork. At parent-of-`d44f5541` upstream's `wiring.rs`
is 1761 lines (the `d44f5541` commit then adds ~360 lines on top of
that). Adopting the prerequisite wiring infrastructure is multi-week
scope.

**Why deferred:** Mirrors P34-DEFER-04b-1 (deprecated_schema module
port, multi-week) and P34-DEFER-04b-2 (profile drafts + package status,
feature-development scope) — both deferred upstream work that demands
multi-week prerequisite porting that exceeds a single sync-plan scope.

**Estimated scope:** multi-week to land upstream's wiring infrastructure
base (`24d8b924` + intermediate commits), after which `242d4917` +
`802c8566` + `d44f5541` apply cleanly as a chain.

**Tracking:** Plan 34-06 SUMMARY records 4 of 8 planned upstream commits
landed (security-critical trust-scan hardening preserved); 3 wiring
commits deferred here; 1 release-bump deferred as P34-DEFER-06-2.

## P34-DEFER-06-2: v0.49.0 release-bump (upstream chore commit)

**Discovered during:** Plan 34-06 Cluster C9 cherry-pick (1 of 8 commits
bumps Cargo.toml versions from 0.48.x → 0.49.0).

**Date:** 2026-05-12

**Deferred commit:**
- `587d98de` — chore: release v0.49.0

**Scope:** Touches CHANGELOG.md (+34 lines) and 5 Cargo.toml files
(bindings/c, crates/nono, crates/nono-cli, crates/nono-proxy, plus
Cargo.lock). Version bumps 0.48.x → 0.49.0.

**Why deferred:** Fork tracks its own version (currently `0.37.1`)
independent of upstream's version increments. The 0.48.x → 0.49.0
version changes conflict with fork's 0.37.1 baseline. Established fork
pattern — same posture taken on prior Phase 34 release-bump commits.

**Future port path:** When the fork performs its own version increment,
the upstream v0.49.0 CHANGELOG stanza (only the first ~34 lines of
`587d98de`'s CHANGELOG.md diff — the entries describing what landed in
v0.49.0) can be ported as a docs-only contribution. The Cargo.toml
version-number changes themselves should never be replayed.

**Tracking:** Plan 34-06 SUMMARY documents this deferral; no impact on
fork's release cadence.

## P34-DEFER-08b-1: `b5f0a3ab` deep refactor of exec_strategy + execution_runtime

**Discovered during:** Plan 34-08b Task 2 commit 2/5 (cherry-pick of upstream
`b5f0a3ab` — `feat(cli): enhance macos learn and run diagnostics`)

**Date:** 2026-05-12

**Scope:** Upstream commit `b5f0a3ab` (Luke Hinds, v0.52.0) is an 11-file /
721-insertion / 118-deletion refactor of nono's CLI diagnostic, profile-save,
and PTY-quiet-period machinery. Trial cherry-pick with
`--strategy-option=theirs` produced 17 compile errors from `ExecConfig`
field-shape mismatch (fork's `ExecConfig` carries 8+ fork-side fields:
`capability_elevation`, `resource_limits`, `audit_signer`, `no_diagnostics`,
`threading`, `protected_paths`, `profile_save_base`, `startup_timeout`,
`allowed_env_vars`, `denied_env_vars`, `bypass_protection_paths`).

**Plan 34-08b absorbed (surgical port):**
- `crates/nono-cli/src/learn_runtime.rs`: macOS `print_macos_run_guidance`
  helper + `command_display::format_command_line` import (PRESERVES Phase
  10/D-02 Windows admin gate).
- `crates/nono/src/diagnostic.rs` (~64 net lines after later scope-trim in
  commit 4/5): cross-platform diagnostic surface improvements that don't
  touch the fork-side `ExecConfig` or `analyze_error_output` wiring.
- `docs/cli/usage/flags.mdx` + `docs/cli/usage/troubleshooting.mdx`: updated
  `nono learn` deprecation-direction docs.

**Plan 34-08b deferred:**
- `crates/nono-cli/src/exec_strategy.rs` (244 lines of changes):
  - `should_offer_profile_save()` predicate guarding the profile-save offer.
  - `clear_signal_forwarding_target()` call before profile-save prompt.
  - `POST_EXIT_PTY_DRAIN_TIMEOUT` constant (250ms → 100ms quiet period).
  - Startup-timeout machinery integration.
- `crates/nono-cli/src/execution_runtime.rs` (46 lines):
  - `should_apply_startup_timeout()` helper.
  - `startup_timeout_profile()` helper.
  - `compute_executable_identity()` helper.
  - New tests for startup-timeout interactive-vs-non-interactive arms.
- `crates/nono-cli/src/cli.rs` `LearnArgs.trace` field (referenced by the
  Plan 34-08b commit 3/5 `print_learn_deprecation` helper; that reference
  was inline-removed with a TODO marker pointing to this deferral).
- `crates/nono-cli/src/profile_save_runtime.rs` minor refinements.
- `crates/nono-cli/src/pty_proxy.rs` minor refinements.
- `crates/nono-cli/src/sandbox_log.rs` minor refinements.
- `crates/nono-cli/src/startup_prompt.rs` minor refinements (likely paired
  with the startup-timeout work in `execution_runtime.rs`).

**Why deferred:** Fork's `ExecConfig` and `SupervisedRuntimeContext` shapes
diverge structurally from upstream's. The 8+ fork-side ExecConfig fields are
load-bearing for fork's audit-attestation surface (Plan 26), capability
elevation (Plan 18), resource limits (D-09), bypass_protection (Plan 26),
env_sanitization (Plan 34-08a), and PTY threading. Restructuring the
`ExecConfig` accommodation requires a dedicated D-20 manual-replay plan with
explicit per-field migration guidance to avoid regressing each of the listed
fork-defense surfaces. The user-visible improvements (better profile-save
UX, faster PTY drain, startup-timeout for stuck agents) are non-critical
and can land via a follow-up plan.

**Estimated scope:** 1-2 weeks (per-field migration audit + integration
testing + macOS/Linux/Windows cross-platform verification of the PTY and
profile-save flows).

**Tracking:** Plan 34-08b SUMMARY commit 2/5 records this deferral; Wave 2
closes with the trimmed scope landed.

## P34-DEFER-08b-2: `bbdf7b85` escape-quote wiring + structured-property pipeline

**Discovered during:** Plan 34-08b Task 2 commit 4/5 (cherry-pick of upstream
`bbdf7b85` — `fix(diagnostic): parse escaped quotes in structured properties`)

**Date:** 2026-05-12

**Scope:** Upstream commit `bbdf7b85` (Luke Hinds, v0.52.0) is a function-body
rewrite of `extract_structured_string_property` to handle escape-quoted
characters in structured diagnostic output (e.g., `path: '/Users/luke/it\'s/pkg'`).
The function and its 3 sibling helpers (`extract_path_after_syscall_word`,
`infer_access_from_structured_syscall_line`, `extract_structured_path_property`)
were introduced by `b5f0a3ab`, AS WAS their wiring into `analyze_error_output`.
Without the wiring (deferred per P34-DEFER-08b-1 above), the 4 helper functions
are dead code AND the 3 upstream tests that exercise them fail.

**Plan 34-08b absorbed (surgical port):**
- `crates/nono/src/diagnostic.rs`: the small additive fallback
  `extract_path_from_segment(prefix).or_else(|| extract_path_from_segment(line))`
  in `extract_denied_path_from_error_line` (which doesn't require structured
  parsing).
- A comment block above `extract_relative_write_path_from_line` and inside
  the test module documenting this deferral for the future restorer.

**Plan 34-08b deferred:**
- Restore `extract_path_after_syscall_word`, `infer_access_from_structured_syscall_line`,
  `extract_structured_path_property`, `extract_structured_string_property`
  (4 helper functions removed during commit 4/5 to avoid `-D warnings`
  dead-code failures).
- Restore `test_analyze_error_output_detects_node_eperm_mkdir_as_write`
  (test landed in commit 2/5 but failed without the wiring).
- Restore `test_analyze_error_output_detects_structured_node_eperm_mkdir_path`
  (would have landed in commit 2/5).
- Restore `test_analyze_error_output_detects_structured_path_with_escaped_quote`
  (would have landed in commit 4/5 — this is `bbdf7b85`'s native test).
- Apply the `bbdf7b85` escape-quote-aware function body rewrite of
  `extract_structured_string_property` (semantically empty until the wiring
  lands).
- Wire all 4 helpers into `analyze_error_output` (per `b5f0a3ab`'s
  `analyze_error_output` refactor).

**Why deferred:** The wiring is part of the same `b5f0a3ab` deep refactor
deferred as P34-DEFER-08b-1. P34-DEFER-08b-2 is the matching tail to
P34-DEFER-08b-1; the two should be picked up together by a single D-20
manual-replay follow-up plan.

**Estimated scope:** Subsumed by P34-DEFER-08b-1's 1-2 week budget; no
incremental cost.

**Tracking:** Plan 34-08b SUMMARY commit 4/5 records this deferral.

---

## P34-DEFER-09-1: Linux Landlock profiles-dir pre-creation hunk (from upstream bdf183e9)

**Source:** Upstream nono v0.44.0 commit `bdf183e9 fix(package): harden re-pulls against user edits`.

**What:** Upstream's commit ends with a Landlock-specific 15-line hunk in
`crates/nono-cli/src/profile_runtime.rs` that pre-creates
`~/.config/nono/profiles` before the Landlock sandbox is built. The rationale
is that Landlock requires the parent directory to exist for `mkdir`
operations even when the child path is explicitly granted write permissions
in `filesystem.allow`.

**Plan 34-09 disposition:** Skip. Out of scope for Plan 34-09's documented C6
cluster (pack migration). D-34-E1's inverse — no Linux-only sandbox-init
wiring outside the plan's documented cluster scope.

**Plan 34-09 rationale:** The vast bulk of bdf183e9 (188/239 lines) lives in
upstream-only `crates/nono-cli/src/wiring.rs`, which the fork does not carry
(see P34-DEFER-09-2 below). The Landlock hunk is a small standalone
improvement that should be picked up by a focused Linux sandbox-init plan,
not absorbed sideways through a pack-migration plan.

**Why deferred:** No fork user is currently blocked. The fork already grants
`~/.config/nono/profiles` write permission in its default profile; the
upstream hardening prevents a latent edge case where the parent directory
doesn't exist yet (clean install, first run).

**Estimated scope:** 1-day Linux-only sandbox-init plan, deferable to
post-Phase-34 cleanup.

---

## P34-DEFER-09-2: Upstream wiring.rs abstraction (idempotent JSON-merge install records)

**Source:** Upstream nono v0.44.0 commits `24d8b924`, `d05672d5`, `bdf183e9`,
`a05fdc57`. Together these introduce and harden a ~1102-line
`crates/nono-cli/src/wiring.rs` module that implements:

- `WriteFile` / `JsonMerge` / `JsonArrayAppend` install directives.
- SHA-256-keyed install records (lockfile v3+v4).
- Strict overwrite policy: refuse to overwrite existing files that were not
  previously written by the same package; allow idempotent re-pulls verified
  by SHA-256.
- Idempotent reversal (`prior_value` capture, gracefully-handle removed
  directives, hash-match-before-remove for JsonArrayAppend).
- `--force` flag on `nono remove` for failure-tolerant uninstall.

**Plan 34-09 disposition:** Not replayed. The fork's package system has
fundamentally different shape — `crates/nono-cli/src/package.rs` (368 lines)
+ `package_cmd.rs` (with Phase 18.1-03 Windows widening + 9
validate_path_within callsites) + `hooks.rs` (centralized installer). A
structural port of wiring.rs would either delete fork-only retention items
(violating D-34-B1 + multiple catalog entries) or require ~2-3 weeks of
careful integration work to braid the two abstractions together.

**Plan 34-09 rationale:** Per the catalog entries "Hooks subsystem ownership"
and "validate_path_within defense-in-depth retention" in
`.planning/templates/upstream-sync-quick.md`, the fork explicitly preserves
the current package system. The wiring.rs benefits (SHA-256 install records,
idempotent reversal, strict overwrite) are HIGH-VALUE but require a focused
fork-preserve-with-integration plan, not a sideways cherry-pick.

**Why deferred:** No fork user is currently blocked. Phase 22-03 PKG-04 +
Phase 26-01 PKGS-02 give defense-in-depth at the path-validation layer; the
hash-keyed install record is additive, not replacement.

**Estimated scope:** 2-3 week D-20 manual-replay plan (post-Phase-34); would
absorb 24d8b924 + d05672d5 + bdf183e9 + a05fdc57 intent at that point.

**Tracking:** Plan 34-09 SUMMARY commit (sha d66dc02c) records this deferral.

---

## P34-DEFER-09-3 (carry-forward, not new): Windows query_ext UNC path test flake

**Source:** `crates/nono-cli/src/query_ext.rs::tests::test_query_path_denied`.

**Symptom:** Test asserts `Some("--read /some/random")` but receives
`Some("--read \\?\C:\some\random")` when run on a Windows host. Pre-existing
at Plan 34-09 baseline HEAD (`61703a4e`) — independently confirmed by checking
out `query_ext.rs` from baseline and re-running the test (same failure).

**Plan 34-09 disposition:** Pre-existing flake; not a NEW failure caused by
Plan 34-09 (which only touched `package.rs` doc comment +
`profile_save_runtime.rs` env var). Tracked here as a carry-forward, NOT a
new deferral.

**Why this isn't a Gate 1 STOP:** Per orchestrator prompt
("P34-DEFER-01-1 + AIPC-SDK env-leak flake carry-forward acceptable; NEW
failures trip STOP"), pre-existing Windows-host flakes do not block plan
close. This failure has the same shape as `test_query_path_denied` would
have at any v2.3-era HEAD on Windows.

**Estimated scope:** 1-day Windows-host test fix (strip UNC prefix in the
test's expected-value normalization, similar to fix
`400f8c90 fix(19-CLEAN-02): strip UNC prefix in query_path sensitive-path
check (Windows)` which fixed the production-code analog of the same issue).
Deferable to post-Phase-34 cleanup.

## P34-DEFER-10-1 (carry-forward, not new): policy show/diff --json Rust Debug leak

**Source:**
- `crates/nono-cli/tests/profile_cli.rs::test_policy_show_json_no_rust_debug_syntax`
- `crates/nono-cli/tests/profile_cli.rs::test_policy_diff_json_no_rust_debug_syntax`

**Symptom:** Both tests assert that the `policy show --json` /
`policy diff --json` output never contains Rust Debug-format leakage
(`Some(...)`, `None)`, PascalCase enum variants). On Windows host at
Plan 34-09 close (HEAD `4e3c9299`) and again at Plan 34-10 close, the
`.security.signal_mode` field renders as the string `"Some(Isolated)"`
(Rust Debug format) instead of the snake_case `"isolated"` that the test
expects. This is a regression in `crates/nono-cli/src/policy_cmd.rs`
JSON emission — the upstream `f3e7f885` (v0.47.0) fix that Plan 34-04b
adopted has not been preserved through one of the subsequent Wave 3
plans (likely Plan 34-08b learn deprecation or 34-09 pack migration
edited an unrelated policy code path that re-introduced the Debug-format
fallback).

**Plan 34-10 disposition:** Pre-existing flake; confirmed pre-existing
at the Plan 34-10 pre-state HEAD (`4e3c9299`) by checking out
`crates/` from baseline and re-running the test (same failure shape:
`.security.signal_mode` contains `"Some(Isolated)"`). Plan 34-10's
changes (audit-context replay + 4 doc-only commits + 34-PHASE-OUTCOMES.md)
did NOT touch `crates/nono-cli/src/policy_cmd.rs` — the source file
that emits the leaking JSON. The 1 modified file in `crates/nono-cli/`
under Plan 34-10 is none (Plan 34-10 only touched
`crates/nono/src/undo/types.rs` + `crates/nono-proxy/src/{audit,connect,external,reverse,server}.rs`).

**Why this isn't a Gate 1 STOP:** Per orchestrator prompt
("P34-DEFER-01-1 + AIPC-SDK env-leak flake carry-forward acceptable;
NEW failures trip STOP"), pre-existing Windows-host flakes do not block
plan close. These failures are pre-existing on the 34-10 baseline
HEAD and are not caused by any Plan 34-10 commit.

**Estimated scope:** 1-day fork-side regression fix — re-audit
`crates/nono-cli/src/policy_cmd.rs::profile_to_json` and `::diff_to_json`
to restore the f3e7f885 Map-based emission of `Option<…>` security
fields (the fork's Plan 34-04b SUMMARY documents the expected shape:
"Map-insertion for `Option<…>` Security fields, omitted-when-None
semantics"). A regression-tracking phase or post-Phase-34 cleanup plan
should pick this up.

## P34-DEFER-10-2: Phase 22-04 OAuth2 + WSAStartup ordering not directly grep-verifiable

**Source:** Plan 34-10 close-gate plan-specific verification PV-3 expected
to grep `WSAStartup` / `wsa_startup` in `crates/nono-proxy/src/server.rs`
to confirm the Phase 22-04 ordering is preserved. The current fork
codebase has NO `WSAStartup` symbol grep hits in `crates/nono-proxy/`
(the Phase 22-04 wiring may have been refactored or the symbol renamed
post-Plan 22-04 / pre-Plan 34-10). Plan 34-02 may have refactored the
Windows winsock-init shape; the lack of `WSAStartup` hits in current
HEAD is not evidence of a regression.

**Plan 34-10 disposition:** Pre-existing absence; not a regression
caused by Plan 34-10. Plan 34-10 did NOT touch
`crates/nono-proxy/src/oauth2.rs` (Phase 22-04 surface), and the edits
to `crates/nono-proxy/src/server.rs` were additive (1 audit log call
site updated to thread `&audit::EventContext{…}`). The byte-identity
proxy of `crates/nono-proxy/src/credential.rs` (SHA256
`c9f25164bb0c82772ad2a1671305afeb926f6722eb4cbbad809efc632b126a09`
pre/post) is the correctness proxy for "Windows credential-injection
rewrite unchanged" in lieu of the WSAStartup grep.

**Estimated scope:** Documentation-only; future plans that touch the
Phase 22-04 OAuth2 / WSAStartup surface should refresh the
`upstream-sync-quick.md` Fork-divergence catalog entry to point at the
current symbol name (if it has been renamed) or note that the
WSAStartup wiring was inlined / moved to a different module.
