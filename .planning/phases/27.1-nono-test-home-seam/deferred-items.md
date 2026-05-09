# Deferred Items — Phase 27.1

Out-of-scope discoveries during Phase 27.1 execution. These pre-existing issues
are NOT caused by Phase 27.1 changes and are deferred for future cleanup.

## Pre-existing clippy errors in `crates/nono-cli/src/exec_strategy_windows/supervisor.rs`

**Discovered during:** Plan 27.1-01 Task 1 (clippy verification)
**Status:** Pre-existing on base commit `18e8e4ea` (verified)
**Errors:**
- `supervisor.rs:788:45` — `collapsible_match` clippy lint
- `supervisor.rs:800:45` — `collapsible_match` clippy lint

These trigger `-D warnings` clippy failures. Verified pre-existing (not caused by
Phase 27.1 changes) by inspection of the unmodified file. Phase 27.1 acceptance
criteria's `cargo clippy -p nono-cli -- -D warnings` requirement is satisfied
for the changed file (`crates/nono-cli/src/config/mod.rs`) — the failures are
in unrelated files.

**Recommended follow-up:** Quick task to apply the clippy `collapsible_match`
suggestions in `supervisor.rs`. Estimated <15 minutes. Not blocking 27.1.

## Pre-existing clippy errors in `crates/nono/src/manifest.rs`

**Discovered during:** Plan 27.1-01 Task 1 (full workspace clippy)
**Errors:**
- `manifest.rs:95` — `collapsible_match` clippy lint
- `manifest.rs:103` — `collapsible_match` clippy lint

Out of scope per D-19 invariant (`crates/nono/` byte-identical). Cannot fix in
Phase 27.1.

**Recommended follow-up:** Address in a `crates/nono/`-targeted housekeeping
plan post-v2.3.

## Pre-existing clippy errors in `crates/nono-cli/src/audit_commands.rs` test module

**Discovered during:** Plan 27.1-03 Task 3 (running `cargo clippy -p nono-cli --tests`)
**Status:** Pre-existing on commit `6275cfb1` (verified by `git stash` round-trip)
**Errors:** ~15 errors including:
- `audit_commands.rs:854` — `useless_vec` (test-fixture vec! → array suggestion)
- Multiple `collapsible_if`, `format_args` style lints
- `audit_session.rs:333` — unused imports `RollbackStatus`, `SessionMetadata`

These trigger `-D warnings` clippy failures on `cargo clippy --tests`. Out of scope
per the executor SCOPE BOUNDARY rule (not caused by Plan 03 changes; the
audit_attestation integration test target itself is clippy-clean).

**Recommended follow-up:** Combine with the `supervisor.rs` follow-up into a single
`crates/nono-cli/`-wide clippy cleanup task (~15-30 min). Not blocking 27.1.

## Phase 27.1 Plan 03 v2.4 production follow-ups (Blocker 3 resurfaced)

**Discovered during:** Plan 27.1-03 Task 3 (Windows host verification)
**Status:** Surfaced; tests re-#[ignore]'d per D-27.1-14 contingency

### v2.4-FU-1: Wire `audit_session::load_session` into `audit_commands.rs`

**Issue:** `crates/nono-cli/src/audit_commands.rs:12` imports `load_session` from
`crate::rollback_session`, which only inspects `<home>/.nono/rollbacks/<id>/`.
Audit-only sessions (created by `--audit-integrity` without `--rollback`) live at
`<home>/.nono/audit/<id>/` and are unfindable by `nono audit verify` and
`nono audit show`. The audit-aware loader at `audit_session.rs:160` already
implements correct dual-root semantics but is gated behind `#[allow(dead_code)]`.

**Fix:** Swap the import in `audit_commands.rs` from `rollback_session` to
`audit_session`, then remove the `#[allow(dead_code)]` attributes from
`audit_session::{discover_sessions, load_session, remove_session, SessionInfo}`.
This is a small change but DOES alter `audit list/cleanup` semantics (they would
discover audit-only sessions they previously missed — generally correct, but
requires test updates).

**Estimated effort:** 30-60 min including unit tests for the changed code paths.

### v2.4-FU-2: Decide bundle target for `--rollback --audit-sign-key` sessions

**Issue:** `audit_attestation::sign_session_attestation` writes the bundle to
`session_dir`, which is `<rollback>/<id>/` when `rollback_active`. Test 2
(`rollback_signed_session_verifies_from_audit_dir_bundle`) asserts the bundle
should be at `<audit>/<id>/audit-attestation.bundle`. Either:
- (a) Mirror the bundle to audit_dir at sign time, OR
- (b) Make `audit verify` look up bundles in both roots, OR
- (c) Update the test to look in the rollback dir for the bundle.

The test name suggests the design intent was (a). This is non-trivial production
architecture; needs a design decision and impact analysis (does the bundle in
audit_dir survive rollback cleanup? Should audit_verify check both roots even
when v2.4-FU-1 lands? etc.).

**Estimated effort:** 1-2 hours including the design decision and test updates.

### v2.4-FU-3: Re-enable both audit-attestation tests after v2.4-FU-1 + v2.4-FU-2

After both production fixes land, the tests can be re-enabled. The
`#[ignore = "..."]` attributes (and the 49-line comment block above Test 1) can
be removed. The `setup_isolated_home` directory pre-creation should remain (it's
defensive against future canonicalize-before-exists patterns).

**Estimated effort:** 15 min including running the suite on a Windows host.

## Phase 27.2 v2.5 production follow-ups (audit-verify surface coordinated bump)

**Created during:** Phase 27.2 close (REQ-AAHX-01..03 closed via D-27.2-01..13)
**Status:** Surfaced; deferred to v2.5 milestone

### v2.5-FU-1: Remove `cmd_verify` back-compat shim

**Issue:** D-27.2-02 introduces a one-shot `tracing::warn!`-on-fallback shim in `audit_session::load_session` (consumed by `audit_commands::cmd_verify` per Phase 27.2 Plan 01) that lets verification succeed when bundles live at the legacy `<rollback>/<id>/audit-attestation.bundle` path (older `nono` versions, pre-Phase-27.2). The shim is intentionally narrow but adds a `Path::exists` + `canonicalize` check on the cold-path verify per session.

**Fix:** Hard cutover. `cmd_verify` (via `audit_session::load_session`) looks up bundles ONLY at `<audit_root>/<id>/audit-attestation.bundle`; the rollback-root fallback iteration is deleted. The `warn_once_legacy_bundle_path` helper and its `OnceLock<()>` guard are deleted. Pairs with v2.5-FU-2 below as a coordinated `cmd_verify` v2 schema bump (see `docs/architecture/audit-bundle-target.md` § "Backward-compat shim contract" for the locked removal milestone).

**Estimated effort:** 15-30 min (delete the rollback-root entry from the `roots` array in `audit_session::load_session`, delete the `warn_once_legacy_bundle_path` helper and its sole call site, delete any unit test that exercises the fallback path).

### v2.5-FU-2: `cmd_verify` v2 JSON schema (nested `attestation` object)

**Issue:** D-27.2-08 keeps `cmd_verify`'s flat JSON shape (`json["attestation_present"]`, `json["attestation_valid"]`) for Phase 27.2 to avoid coupling Test 2's re-enablement to a schema bump. The semantically richer nested shape (`json["attestation"]["present"]`, `json["attestation"]["signature_verified"]`, `json["attestation"]["merkle_root_matches"]`, `json["attestation"]["session_id_matches"]`, `json["attestation"]["verification_error"]`) was preserved in Test 2's original assertion intent (now adapted to the flat shape per Phase 27.2 Plan 04) and is the natural output once the audit-vs-rollback architectural split is fully landed.

**Fix:** Bump `cmd_verify` to a v2 schema with nested `attestation` object. Flat keys deprecated for one version with parallel emission, then removed in v2.6 (or per the deprecation policy decided at v2.5 scope-lock). Coordinate release with v2.5-FU-1 since both affect the audit-verify surface; recommend a single schema-version-bump commit landing both changes.

**Estimated effort:** 1-2 hours including schema-bump migration tests, `docs/cli/audit-verify.md` schema documentation update, and Test 2 re-asserting the nested shape.
