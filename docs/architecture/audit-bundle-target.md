# Audit Bundle Target

**Status:** Accepted
**Date:** 2026-05-05
**Phase:** 27.2 (v2.3 Audit-Attestation Test Re-Enablement)
**Requirement:** REQ-AAHX-02
**Supersedes:** Plan 22-05a Decision 5 ("for backward compatibility" dual-location rationale)

## Context

Phase 22-05a Decision 5 (v2.2) split audit-only sessions to `<audit_root>/<id>/` "for namespace separation" while keeping rollback-active sessions writing the audit attestation bundle to `<rollback_root>/<id>/audit-attestation.bundle`. The split was a partial migration: audit-only flows landed in the new namespace; `--rollback` flows did not. The disposition was recorded as "for backward compatibility" — meaning, in practice, that v2.2 deferred the question of whether the dual-location shape was the desired endpoint.

Phase 27.1 Plan 03 (v2.3, 2026-05-04) attempted to re-enable Phase 27's deferred audit-attestation integration tests on a Windows host using the Phase 27.1 `NONO_TEST_HOME` seam. The seam itself worked end-to-end (`nono run --audit-integrity` correctly wrote sessions to `<NONO_TEST_HOME>/.nono/audit/<id>/`), but Test 2 (`rollback_signed_session_verifies_from_audit_dir_bundle`) failed because the supervisor wrote the bundle to `<rollback_root>/<id>/` while the test asserted `<audit_root>/<id>/`. Phase 27.1 D-27.1-14 large-fix branch surfaced this as v2.4-FU-2 ("bundle-target architecture decision") and re-`#[ignore]`'d the test pending the design call.

The deeper issue surfaced is non-repudiation: under the v2.2 dual-location shape, `rm -rf ~/.nono/rollbacks/<id>/` deletes the audit attestation bundle along with the snapshot. An adversary (or a careless cleanup script) can destroy the cryptographic evidence that the session ever ran. Audit attestation is the non-repudiation mechanism; locating it inside a directory designed for mutable, user-discardable rollback artifacts is a structural mismatch.

This ADR finishes the namespace-separation migration started in v2.2: the bundle ALWAYS lives at `<audit_root>/<id>/audit-attestation.bundle` regardless of `--rollback` flag state. Snapshot artifacts (`changes/`, `manifest.json`) continue to live under `<rollback_root>/<id>/` when `--rollback` is set. A back-compat verification shim preserves the ability to verify bundles signed by older `nono` versions whose bundles are still at the legacy `<rollback>/<id>/` location.

### Goals

This ADR commits to:

- One canonical bundle location independent of `--rollback` flag state.
- Audit attestation bundle outlives rollback cleanup (`rm -rf ~/.nono/rollbacks/<id>/` no longer destroys it).
- Backward-compatible verification of bundles written by older `nono` versions, with a one-shot deprecation warning so operators can re-sign at their leisure.
- A documented v2.5 milestone for hard-cutover removal of the back-compat shim.

### Non-goals

This ADR explicitly does NOT commit to:

- Migrating existing on-disk bundles. Verification still works via the shim; re-signing is operator-driven.
- Changing `cmd_verify`'s JSON output schema in this phase. The current flat shape (`json["attestation_present"]`, `json["attestation_valid"]`) is preserved verbatim. The richer nested shape is deferred to v2.5-FU-2.
- Touching `crates/nono/` (D-27.2-11 invariant). All code changes live in `crates/nono-cli/`.
- Resolving the WR-01 split-brain home-resolution finding from Phase 27.1 (`validated_home()` vs `nono_home_dir()`). Out of scope per CONTEXT § Deferred Ideas.

## Decision Table

| Option | Bundle Target on `--rollback` | Verification Path | Verdict |
|--------|-------------------------------|-------------------|---------|
| **A (chosen)** | `<audit_root>/<id>/audit-attestation.bundle` always | Audit-first lookup; rollback-root fallback shim with one-shot `tracing::warn!` until v2.5 | **Accepted** |
| B | `<rollback_root>/<id>/...` when `--rollback`; `<audit_root>/<id>/...` otherwise; verify learns dual-root | Permanent dual-root | Rejected: codifies the dual-location complexity instead of finishing the namespace migration. Permanent verifier complexity for no security gain. |
| C | Test rewrite — accept current production behavior (bundle at `<rollback>/<id>/` when rollback-active) | Unchanged | Rejected: codifies the non-repudiation hole. Test name `rollback_signed_session_verifies_from_audit_dir_bundle` would have to be renamed to assert wrong intent. |

The chosen Option A finishes the migration that Plan 22-05a Decision 5 started: audit-only sessions migrated in v2.2; `--rollback` sessions migrate in v2.3 Phase 27.2.

## Decision

The audit attestation bundle is written to `<audit_root>/<id>/audit-attestation.bundle` regardless of `--rollback` flag state. When `--rollback` is set, snapshot artifacts (`changes/`, `manifest.json`, etc.) continue to land under `<rollback_root>/<id>/` — only the bundle target moves.

`cmd_verify` resolves session lookup audit-first (`audit_session::load_session`) with a rollback-root fallback shim. On a fallback-root hit, the verifier emits exactly one `tracing::warn!` per process identifying both the legacy and canonical paths and the v2.5 removal milestone. The shim is removed in v2.5 (see the shim contract subsection below; tracked as v2.5-FU-1 in `.planning/phases/27.1-nono-test-home-seam/deferred-items.md`).

## Consequences

### Positive

- **Non-repudiation closed.** `rm -rf ~/.nono/rollbacks/<id>/` no longer destroys the audit attestation bundle. Audit evidence outlives rollback cleanup.
- **Test 2 (`rollback_signed_session_verifies_from_audit_dir_bundle`) becomes correct by construction.** The test's `audit_dir.join("audit-attestation.bundle").exists()` assertion now passes for both `--rollback` and audit-only flows.
- **Plan 22-05a Decision 5's namespace separation is finished.** Audit-only sessions and rollback-active sessions both put their cryptographic record in the same canonical place. No more "depends on flags" routing.
- **Verifier's audit-first lookup is the natural shape post-migration.** The audit-aware loader at `audit_session.rs:160-198` was already designed for audit-first / rollback-fallback semantics; v2.3 Phase 27.2 simply wires it in.

### Negative

- **Verify path needs the rollback-root fallback shim until v2.5.** One extra `Path::exists` + `canonicalize` check on the cold path (when the audit-root lookup misses). Warm path (post-Phase-27.2 sessions) hits audit-root only — no perf regression.
- **Existing rollback-active bundles on disk fire the deprecation warning until re-signed.** Operators who upgrade from v2.2 to v2.3 see a one-shot `tracing::warn!` per process when verifying a pre-Phase-27.2 session. Documented in CHANGELOG (v2.3 entry) and via the warning text itself.
- **Two `create_dir_all` calls per `--rollback --audit-integrity --audit-sign-key` session** instead of one. One for `<audit_root>/<id>/` (bundle dir), one for `<rollback_root>/<id>/` (snapshot dir). Negligible perf cost (one extra `mkdir`-equivalent syscall).

### Backward-compat shim contract

- **Trigger:** `cmd_verify` finds the bundle at `<rollback_root>/<id>/audit-attestation.bundle` after missing it at `<audit_root>/<id>/audit-attestation.bundle`.
- **Action:** Verify proceeds normally (the bundle is still cryptographically valid; only its location is legacy). The verifier emits exactly one `tracing::warn!` per process identifying both the legacy and canonical paths and instructing the operator to re-sign affected sessions if they want to clear the warning.
- **Warning text** (locked in `audit_session::warn_once_legacy_bundle_path`): `"audit-attestation bundle found at legacy {legacy_path} path; canonical location is {canonical_path}. This compatibility shim is removed in v2.5 -- re-sign affected sessions if needed."`
- **Removal milestone:** v2.5-FU-1 (see `.planning/phases/27.1-nono-test-home-seam/deferred-items.md` § "Phase 27.2 v2.5 production follow-ups"). At v2.5 close, `cmd_verify` looks up bundles ONLY at `<audit_root>/<id>/audit-attestation.bundle`; the rollback-root fallback is deleted; the `warn_once_legacy_bundle_path` helper and its `OnceLock` guard are deleted.

## References

### Internal

- `.planning/REQUIREMENTS.md` § AAHX (REQ-AAHX-02 acceptance criteria)
- `.planning/phases/27.2-audit-attestation-test-re-enablement/27.2-CONTEXT.md` (decisions D-27.2-01, D-27.2-02, D-27.2-03, D-27.2-04, D-27.2-06)
- `.planning/phases/27.1-nono-test-home-seam/27.1-03-SUMMARY.md` (origin of FU-2; § "Gap 2 (Test 2 failure): Bundle target mismatch")
- `.planning/phases/27.1-nono-test-home-seam/deferred-items.md` § "Phase 27.2 v2.5 production follow-ups" (v2.5-FU-1 shim-removal milestone, v2.5-FU-2 JSON v2 schema)

### Source code

- `crates/nono-cli/src/audit_attestation.rs:155` (bundle write site: `bundle_path = session_dir.join(ATTESTATION_BUNDLE_FILENAME)`)
- `crates/nono-cli/src/rollback_runtime.rs::create_audit_state` (post-Phase-27.2: `session_dir` always derived from `audit_session::ensure_audit_session_dir`)
- `crates/nono-cli/src/audit_session.rs::load_session` (audit-first / rollback-fallback loader; live consumer added in Phase 27.2 Plan 01)
- `crates/nono-cli/src/audit_commands.rs::cmd_verify` (consumes the audit-aware loader post-Phase-27.2 Plan 01)

### Related ADRs

- `docs/architecture/aipc-unix-futures.md` (Phase 25-02 ADR convention reference; this ADR mirrors its structure)
