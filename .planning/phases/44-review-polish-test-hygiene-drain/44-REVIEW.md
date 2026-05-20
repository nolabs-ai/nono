---
phase: 44-review-polish-test-hygiene-drain
reviewed: 2026-05-20T00:00:00Z
depth: standard
files_reviewed: 25
files_reviewed_list:
  - .config/nextest.toml
  - .github/scripts/check-cli-doc-flags.sh
  - .github/workflows/phase-37-linux-resl.yml
  - crates/nono-cli/src/cli.rs
  - crates/nono-cli/src/diagnostic_formatter.rs
  - crates/nono-cli/src/exec_strategy/supervisor_linux.rs
  - crates/nono-cli/src/format_util.rs
  - crates/nono-cli/src/main.rs
  - crates/nono-cli/src/pack_update_hint.rs
  - crates/nono-cli/src/package_cmd.rs
  - crates/nono-cli/src/platform.rs
  - crates/nono-cli/src/session_commands.rs
  - crates/nono-cli/src/session_commands_windows.rs
  - crates/nono-cli/src/trust_cmd.rs
  - crates/nono-cli/tests/auto_pull_e2e_linux.rs
  - crates/nono-cli/tests/common/test_env.rs
  - crates/nono-cli/tests/deny_overlap_run.rs
  - crates/nono-cli/tests/env_vars.rs
  - crates/nono-cli/tests/resl_nix_linux.rs
  - crates/nono/src/error.rs
  - crates/nono/src/lib.rs
  - crates/nono/src/trust/bundle.rs
  - crates/nono/src/trust/signing.rs
  - crates/nono/src/undo/snapshot.rs
  - docs/cli/usage/flags.mdx
findings:
  critical: 1
  warning: 4
  info: 6
  total: 11
status: issues_found
---

# Phase 44: Code Review Report

**Reviewed:** 2026-05-20
**Depth:** standard
**Files Reviewed:** 25
**Status:** issues_found

## Summary

Phase 44 is the v2.6 REVIEW.md polish + test-hygiene drain. The bulk of the changes are well-scoped, well-tested, and well-commented: the cgroup-v2 hint dedup (WR-02 P37), the platform.rs registry/version-comparator hardening (WR-02/04/06 P43), the pack_update_hint atomic-write + semver-aware comparator (IN-01/WR-03 P43), the format_bytes_short dedup into `format_util.rs` (IN-03 P37), and the test thread-safety migration to the canonical `lock_env()` mutex (D-44-E6) all look correct and ship with regression tests.

One BLOCKER stands out: the WR-09 P37 wiring of `NONO_TRUST_OIDC_ISSUER` in `trust_cmd.rs::verify_*` deviates from the explicit D-44-B3 acceptance spec ("if unset, falls back to current behavior") by silently substituting the GitHub Actions default OIDC issuer when neither `--issuer` nor the env-var is set. The pre-44 behavior was an explicit fail-closed `ok_or_else(...)?` requiring the operator to pass `--issuer` for keyless verify; the post-44 path silently applies an implicit trust anchor, weakening a documented "REQUIRED" CLI argument check. This is a security policy change inconsistent with both CLAUDE.md § Explicit Over Implicit and the original D-32-08 fail-closed design.

The remaining WARNING-level findings cluster around documentation drift (incorrect "load-bearing" claim in `package_cmd.rs::run_outdated`, misleading "Plan 44-02 will wire a Windows consumer" comment in `tests/common/test_env.rs`, overbroad "fail-closed predicate semantics" claim in `platform.rs::compare_versions`) and one test-shape concern (the `deny_overlap_run.rs` either-or assertion combines `"Permission denied"` AND `"No path denials were observed"` with AND, which may not hold if nono's stderr shape changes).

## Critical Issues

### CR-01: WR-09 implicit-default OIDC issuer fallback weakens D-32-08 fail-closed semantics

**File:** `crates/nono-cli/src/trust_cmd.rs:976-984` (multi-subject path) and `crates/nono-cli/src/trust_cmd.rs:1172-1180` (single-file path)
**Issue:** Before Phase 44, `verify_multi_subject_file` and `verify_single_file` required the operator to pass `--issuer` for keyless verification:
```rust
let req_issuer = user_issuer.ok_or_else(|| {
    "keyless bundle requires --issuer <OIDC_URL> \
     (exact match against signer's iss claim)".to_string()
})?;
```
After WR-09, the `None` branch silently calls `trust::signing::configured_oidc_issuer()`, which returns the `NONO_TRUST_OIDC_ISSUER` env-var value OR the canonical `GITHUB_ACTIONS_OIDC_ISSUER` default const when both the env-var and the CLI flag are unset.

This is a deviation from the D-44-B3 acceptance spec recorded in `.planning/phases/44-review-polish-test-hygiene-drain/44-CONTEXT.md:132`:

> "the env var is read; if set, asserts as the trusted OIDC issuer at signature verification time; **if unset, falls back to current behavior**"

Pre-44 "current behavior" when both `--issuer` AND env-var were unset was to ERROR fail-closed. The implementation now silently substitutes `https://token.actions.githubusercontent.com` (GitHub Actions default), so an operator who forgets `--issuer` on `nono trust verify` will silently succeed against any GitHub-Actions-keyless bundle they did not explicitly choose to trust.

The CLI doc at `cli.rs:3046-3049` still says `--issuer` is "REQUIRED for keyless verify; exact match against signer's iss claim" — that doc is now misleading.

CLAUDE.md § Explicit Over Implicit: "Security-relevant behavior must be explicit and auditable." An implicit hard-coded trust anchor that activates when neither CLI flag nor env-var is set is the opposite of explicit.

The identity-regex check still gates the path (`user_identity_pattern.ok_or_else(...)?`), so a verify call without BOTH `--issuer` and `--identity` still fails closed — but a verify call with `--identity` but no `--issuer` now succeeds against any GitHub Actions bundle. Bundles signed via GitLab CI, Buildkite, or any other Sigstore-compatible OIDC issuer cannot be silently substituted because the issuer-equality check at `validate_oidc_issuer(bundle_issuer, req_issuer)` would mismatch — but the GitHub Actions issuer specifically gets a free pass under the implicit default.
**Fix:** Restore the fail-closed `ok_or_else(...)?` requirement for `user_issuer == None && env-var unset`. Keep the env-var fallback (the WR-09 production-wiring intent) only when the env-var is explicitly set:
```rust
let env_issuer: String;
let req_issuer: &str = match user_issuer {
    Some(s) => s,
    None => {
        // Read env var; require it to be explicitly set (no hard-coded default fallback).
        env_issuer = std::env::var("NONO_TRUST_OIDC_ISSUER")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| {
                "keyless bundle requires --issuer <OIDC_URL> or NONO_TRUST_OIDC_ISSUER \
                 env-var (exact match against signer's iss claim)".to_string()
            })?;
        // Eagerly validate URL shape (mirrors configured_oidc_issuer's existing check).
        url::Url::parse(&env_issuer).map_err(|e| {
            format!("NONO_TRUST_OIDC_ISSUER='{env_issuer}' is not a valid URL: {e}")
        })?;
        &env_issuer
    }
};
```
This preserves D-32-08 fail-closed semantics, satisfies the D-44-B3 acceptance spec ("if unset, falls back to current behavior"), and keeps the env-var an opt-in trust anchor (CLAUDE.md § Explicit Over Implicit).

Alternatively, split `configured_oidc_issuer` into two functions: `configured_oidc_issuer_or_default()` (the current implementation, for non-verification call sites that need a default) and `configured_oidc_issuer_required()` (returns Option<String>, no hard-coded fallback) for the verify paths.

## Warnings

### WR-01: `tests/common/test_env.rs` lock_env dead-code comment promises a Plan 44-02 wiring that did not happen

**File:** `crates/nono-cli/tests/common/test_env.rs:74-83`
**Issue:** The `#[allow(dead_code)]` justification on `lock_env`/`ENV_LOCK` says:

> "on Windows the only current consumer is `tests/env_vars.rs`, which uses `EnvVarGuard::set_all` but does NOT yet call `lock_env()` (Plan 44-02 wires that via cargo-nextest subprocess-per-test isolation)."

Plan 44-02 (D-44-D3) explicitly chose cargo-nextest subprocess-per-test isolation INSTEAD of wiring `lock_env()`. See `.config/nextest.toml:10-16` — the two affected env_vars tests are routed through `threads-required = 'num-cpus'`, which serializes them at the nextest scheduler level rather than at the `lock_env` mutex level. So `lock_env` will remain dead-code on Windows in the `env_vars.rs` integration-test binary indefinitely; the "transitional" framing is incorrect.

The function is still legitimately used by `tests/auto_pull_e2e_linux.rs` (Linux-only), so the `#[allow(dead_code)]` is necessary — but the justification is misleading about what will close it.
**Fix:** Update the comment to reflect the actual end-state:
```rust
/// Phase 44 D-44-E5 dead-code justification: on Linux, this lock is acquired
/// at the top of every env-var-mutating test in `tests/auto_pull_e2e_linux.rs`.
/// On Windows, the two known-racy `env_vars.rs` tests are serialized via
/// cargo-nextest subprocess-per-test isolation (`.config/nextest.toml`) rather
/// than via `lock_env()`, so the function appears dead in the Windows
/// integration-test binary. The `#[allow(dead_code)]` is permanent — moving
/// the Windows tests onto `lock_env()` would duplicate the nextest-level
/// isolation and is not planned. If `lock_env()` gains a Windows consumer in
/// the future, the allow can be removed at that time.
```

### WR-02: `package_cmd.rs::run_outdated` "load-bearing two-pass" comment is logically incorrect

**File:** `crates/nono-cli/src/package_cmd.rs:639-657`
**Issue:** The IN-04 comment block claims the two iterator passes are "load-bearing":

> "do NOT collapse these two passes into a single classifier without preserving the unknown vs current distinction."

The actual code is:
```rust
let needs_attention = entries.iter().any(|e| e.status != "current" && e.status != "unknown");
if !needs_attention && entries.iter().all(|e| e.status == "current") { ... }
```

The second clause `entries.iter().all(|e| e.status == "current")` STRICTLY implies the first clause `!needs_attention`: if every entry has status `"current"`, no entry has any non-`{current,unknown}` status, so `needs_attention` is already false. The `if` condition is equivalent to just `if entries.iter().all(|e| e.status == "current")`. The two-pass guard provides defense-in-depth against future drift of `needs_attention` semantics, but the comment's load-bearing claim is logically unsupported as written.

This is documentation drift: a future reader who reads the comment will believe the asymmetry encodes a real distinction (between "no actionable" and "all current") and may be confused by simplifying the code.
**Fix:** Either correct the comment to reflect the actual defense-in-depth intent:
```rust
// The two-pass shape is defense-in-depth: if a future change widens the
// `needs_attention` predicate (e.g., to treat a new third status as
// actionable), the all-current check still guarantees the "All up to date"
// path only fires when every entry is unambiguously current. The two
// predicates are NOT logically independent today — `all(current)` already
// implies `!needs_attention` — but keeping both makes the intent explicit.
```
Or collapse the conditional to its actually-implied form:
```rust
if entries.iter().all(|e| e.status == "current") {
    println!("All installed packs are up to date.");
    return Ok(());
}
```

### WR-03: `deny_overlap_run.rs` either-or assertion requires BOTH "Permission denied" AND "No path denials were observed"

**File:** `crates/nono-cli/tests/deny_overlap_run.rs:117-123`
**Issue:** The D-44-C1 assertion accepts validator pre-flight OR runtime Landlock denial:
```rust
let validator_message = stderr.contains("Landlock deny-overlap");
let runtime_denial = stderr.contains("Permission denied")
    && stderr.contains("No path denials were observed");
assert!(validator_message || runtime_denial, ...);
```

The `runtime_denial` branch requires BOTH `"Permission denied"` AND `"No path denials were observed"` in stderr. This combination is unusual — typically nono's runtime denial would emit `"Permission denied"` from the failed `cat` syscall, and the "No path denials were observed" string sounds like a diagnostic footer that appears when nono's monitor detected NO denials (the opposite of a denial). If both strings appearing simultaneously is an actual property of nono's stderr shape on this code path, the comment should explain WHY — otherwise a future stderr-format change (e.g., dropping the "No path denials were observed" footer when a denial DID occur) would silently break this test.

The CONTEXT.md D-44-C1 wording (line 84) describes the OR shape but does not justify the AND inside `runtime_denial`. The follow-up todo at `.planning/todos/pending/44-class-d-validator-preflight-investigation.md` is the right place to track the validator pre-flight bug, but this test's assertion shape is itself fragile.
**Fix:** Add an explanatory comment in the test body documenting why both strings must be present (presumably: `"Permission denied"` is the inner `cat` error message that nono captures and re-emits, and `"No path denials were observed"` is the diagnostic footer that confirms nono itself did NOT block the operation — i.e., Landlock did, not nono — which is the actual security signal). If the two strings do not actually co-occur in current nono output, weaken the AND to OR or replace with a single regex pattern that matches whichever shape is the load-bearing one.

### WR-04: `is_newer` regression silently disables update hints for legacy non-semver installed packs

**File:** `crates/nono-cli/src/pack_update_hint.rs:302-307`
**Issue:** Pre-44 `is_newer` returned `true` when the installed version was unparseable but the latest version was a valid semver:
```rust
(None, Some(_)) => true, // legacy non-semver installed, new semver release available
```
This was load-bearing for users with pre-semver installed packs (e.g., date-versioned `"2024-12-01"` or git-SHA versioned `"abc123"`): they would see an "update available" hint to the first semver release.

Post-44, the `(None, Some(_))` branch is dropped — the function returns `false` for any unparseable side. The docstring justifies this as "pre-release suppression trumps a possibly-misleading legacy-installed signal", but the trade-off silently removes update hints for an entire user segment.

The WR-03 P43 root bug (pre-release installs false-positiving) is real, but the fix overcorrects: a parseable `latest` with an unparseable `installed` could be disambiguated by checking if `installed` looks date-shaped vs pre-release-shaped vs SHA-shaped, or by adding a separate hint pathway for "installed version unrecognized; latest available is X".
**Fix:** This is a deliberate trade-off per D-44-A4, not necessarily a bug — but the docstring should explicitly acknowledge the lost case so future readers don't think it's a missed branch. Suggested addition to the docstring:
```rust
/// **Trade-off:** the (Unparseable, Parseable) case is suppressed, which
/// means users with pre-semver-tagged installed packs (e.g. date-versioned
/// `"2024-12-01"` or git-SHA `"abc123def"`) will not see update hints. This
/// is intentional: the pre-44 behavior false-positived on pre-release
/// installs (`"1.2.3-beta"`), which was the more common failure mode.
/// If legacy-tag users need hints, a separate "installed version
/// unrecognized" code path could be added without re-introducing the
/// pre-release false positive.
```

## Info

### IN-01: `parse_windows_registry_value` line-skip comment describes new `Some(first)` skip but does not mention the `kind = parts.next()?` early-return

**File:** `crates/nono-cli/src/platform.rs:155-165`
**Issue:** The WR-06 P43 comment at lines 155-158 says:

> "Empty / whitespace-only lines (e.g. the leading blank line in `reg query` output) skip via the `None` branch — do NOT short-circuit the whole function, since the value line we want may appear later in the same blob."

This is accurate for the `let Some(first) = parts.next() else { continue; };` block at line 159-161. But the very next line (165) uses `?`:
```rust
let kind = parts.next()?;
```
If a line has the matching name but no second token (no kind column), `?` returns `None` from the WHOLE function, NOT continuing to the next line. The comment's "do NOT short-circuit the whole function" intent applies only to empty-line skipping, not to malformed lines with a name but no kind.

In practice `reg query` output is structured enough that a name without a kind is unlikely, so this is theoretical. But the comment could be read as a stronger guarantee than the code provides.
**Fix:** Tighten the comment to say "Empty / whitespace-only lines skip via the `None` branch and continue to the next line. A line matching the name but missing the kind column is treated as terminal-malformed and returns `None` from the whole function (acceptable: `reg query` output is consistently structured)."

### IN-02: `compare_versions` "fail-closed predicate semantics" claim is asymmetric

**File:** `crates/nono-cli/src/platform.rs:621-628`
**Issue:** The WR-04 P43 comment says:

> "Mixed numeric/non-numeric: the numeric side sorts greater for fail-closed predicate semantics. CLAUDE.md § Fail Secure — 'alpha' must NOT compare greater than '1' or a version-pinning predicate could be tricked into accepting a non-numeric (e.g. 'alpha') build as newer than the released '1.x' baseline."

The semantic is fail-closed only for `>=` (lower-bound) predicates. For `<=` (upper-bound) predicates, `compare_versions("alpha", "1.0") == Less` means `"alpha" <= "1.0"` evaluates to TRUE, which is the OPPOSITE of fail-closed for an upper bound — a non-numeric build would be accepted as "below the cap".

In practice nono's version predicates appear to be lower-bound-dominant (`min_kernel_version`, `min_macos_version` patterns), so this is not a real footgun today. But the comment's "fail-closed predicate semantics" claim is overbroad as worded.
**Fix:** Narrow the docstring:
```rust
// Mixed numeric/non-numeric: the numeric side sorts greater. This is
// fail-closed for LOWER-BOUND predicates (e.g. `>= 1.0` rejects "alpha")
// but the opposite for upper-bound predicates (`<= 1.0` would accept
// "alpha"). nono's predicate set is lower-bound-dominant; if upper-bound
// predicates are added in the future, they must validate their LHS is
// numeric before comparing.
```

### IN-03: `pack_update_hint::save_state` atomic-write may race on concurrent invocations

**File:** `crates/nono-cli/src/pack_update_hint.rs:248-260`
**Issue:** The IN-01 P43 atomic tmp+rename retrofit is correct for partial-write protection within a single process. But two concurrent `nono run` invocations could both write to the same `pack-update-hints.json.tmp` path (since the tmp filename is deterministic — no PID/timestamp suffix). The second `std::fs::write` to the tmp file would overwrite the first; the first `rename` would succeed; the second `rename` would also succeed but might race with the first. Net effect: one writer's update is silently dropped.

Pre-existing concurrency property (the cache itself is per-process; concurrent invocations would have raced even with the pre-44 single-write code), and the consequence is benign — a missed cache update means slightly more registry traffic next run. Acceptable per D-44-B5 "low-cost change to fix the partial-write window" framing.
**Fix:** Optional defense-in-depth: include a PID or timestamp in the tmp filename:
```rust
let tmp_path = path.with_extension(format!("json.tmp.{}", std::process::id()));
```
This eliminates the concurrent-tmp-overwrite case at the cost of one extra `process::id()` syscall. The rename race remains but is benign.

### IN-04: `supervisor_linux.rs` cgroup-v2 doc block concatenates two paragraphs without separator

**File:** `crates/nono-cli/src/exec_strategy/supervisor_linux.rs:828-855`
**Issue:** The pre-existing fail-fast doc paragraph (lines 828-835) ends with "The path-traversal guard in `detect_from_str` is the lone exception that still returns `NonoError::UnsupportedPlatform(...)` (Phase 37 D-07)." The new IN-06 P37 paragraph (lines 836-855) begins on the very next `///` line without a blank `///` separator, producing a confusing run-on rendered doc. The two paragraphs cover overlapping ground (both list which detection sites use `UnsupportedKernelFeature` vs `UnsupportedPlatform`).
**Fix:** Add a blank `///` separator between the paragraphs and consider consolidating the two summaries into one. Suggested:
```rust
/// ...returns `NonoError::UnsupportedPlatform(...)` (Phase 37 D-07).
///
/// # Cgroup-v2 detection sites (Phase 44 IN-06 P37, REQ-REVIEW-FU-01 D-44-A4)
///
/// All six `NonoError::UnsupportedKernelFeature { feature: "cgroup_v2", ... }`
/// constructions in this module share the LOCKED hint string from
/// [`nono::CGROUP_V2_HINT`]...
```

### IN-05: `auto_pull_e2e_linux.rs` set_all-then-remove_var pattern is correct but fragile

**File:** `crates/nono-cli/tests/auto_pull_e2e_linux.rs:218-226, 277-283, 337-343, 431-437, 530-536`
**Issue:** Each affected test does:
```rust
let _env = EnvVarGuard::set_all(&[
    ...,
    ("NONO_NO_AUTO_PULL", ""),
]);
std::env::remove_var("NONO_NO_AUTO_PULL");
```
The intent is: "set the var to empty so set_all captures the original (for Drop-restore), then immediately remove it so the spawned nono binary doesn't inherit an unparseable empty value to `BoolishValueParser`". This works because `set_all` captures originals at line 37 of `test_env.rs` BEFORE setting values, so Drop correctly restores the pre-test value (or removes if originally unset).

However, the pattern is non-obvious and the inline comment ("set_all with empty string is NOT equivalent to remove — explicitly remove the var after set_all captures its baseline") explains the WHY but not the failure mode if a reader inverts the order. A cleaner pattern would be a `set_all_with_removals` helper on `EnvVarGuard` that takes both vars-to-set and vars-to-remove, captures originals for both, and applies them as a single atomic batch.
**Fix:** Either add a helper:
```rust
impl EnvVarGuard {
    pub fn set_and_remove(set: &[(&'static str, &str)], remove: &[&'static str]) -> Self {
        let mut original = Vec::with_capacity(set.len() + remove.len());
        for (k, _) in set { original.push((*k, std::env::var(k).ok())); }
        for k in remove { original.push((*k, std::env::var(k).ok())); }
        for (k, v) in set { std::env::set_var(k, v); }
        for k in remove { std::env::remove_var(k); }
        Self { original }
    }
}
```
Or accept the existing inline pattern but lift the redundant `remove_var` calls into a shared test helper that hides the set-then-remove sequence behind a single call.

### IN-06: `tests/auto_pull_e2e_linux.rs` IN-05 retry-count widening from 2 to 4 may mask future regressions

**File:** `crates/nono-cli/tests/auto_pull_e2e_linux.rs:309-317`
**Issue:** The retry-count assertion was widened from `<= 2` to `<= 4` to absorb harmless retry growth. The comment says "Any count above 4 indicates the registry client is retrying without bound, which would violate the fail-closed acceptance." But the widening also reduces the regression-detection power: a real bug that doubles the request count from 2 to 3 would now pass silently. A tighter pin (e.g., `assert_eq!(req_count, 2)` with an explicit allow-list of acceptable values) would catch retry-count regressions earlier.

Pre-existing trade-off documented in D-44-B5 — acceptable as documented. Suggesting only to consider exposing the retry count from the production code (e.g., via a `tracing::Span` or a counter metric) so the test can assert a tight value rather than a fuzzy bound.

---

_Reviewed: 2026-05-20_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
