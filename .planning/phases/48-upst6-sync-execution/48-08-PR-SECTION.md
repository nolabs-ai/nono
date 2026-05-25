---
plan_id: 48-08
cluster: C9
cluster_disposition: fork-preserve-deferred
upstream_sha_range: 5f1c9c73..8d774753
upstream_commit_count: 2
verdict: STAY D-20 manual-replay
d_48_c3_regression_test: PASS
generated: 2026-05-25
---

# Plan 48-08 PR Section: Package Manifest + Trust-Bundle Schema (Cluster C9)

## Cluster C9 — Package Manifest + Trust-Bundle Schema

**Disposition:** Fork-preserve → **D-20 manual-replay (deferred)** per D-48-C1 diff-inspection  
**Upstream range:** `5f1c9c73..8d774753` (v0.55.0; 2 commits by Luke Hinds)  
**Phase 47 ledger row:** C9 `fork-preserve-with-upgrade-authority`

---

### What was absorbed

Both C9 upstream commits were replayed fork-side as D-20 manual-replay commits
(Convention Pattern B) rather than cherry-picked with D-19 trailers. Fork divergence
made clean cherry-pick non-viable (~6 conflict sites across 2 files).

**C9-01 (`refactor(48-08)`: replay of `5f1c9c73`)** — Manifest-driven install pipeline:
- Added `installed_artifact_relative_path(artifact: &ArtifactEntry) -> Result<String>`
  helper to `package_cmd.rs` (fork-extended: includes `ArtifactType::Hook` + `Script` arms
  not in upstream).
- Extended `write_supporting_artifacts` to populate `installed_path` + `sha256_digest` in
  each `.nono-trust.bundle` entry (enabling precise offline artifact location for D-32-15).
- Added `validate_bundle_relative_path` to `profile_runtime.rs` (path-component iteration;
  rejects path traversal, absolute paths, empty strings per CLAUDE.md § Path Handling).
- Upgraded `verify_stored_bundles` to use `installed_path` field (fallback to `artifact_name`)
  and `extract_all_subjects` + digest check (stricter than `verify_bundle_subject_name`).

**C9-02 (`feat(48-08)`: replay of `8d774753`)** — Path conflict prevention:
- Added `validate_manifest_install_paths` pre-installation check to detect duplicate
  install paths before any files are written.
- Extended `installed_artifact_relative_path` to guard reserved filenames (`package.json`,
  `.nono-trust.bundle`) — prevents attacker-crafted manifests from poisoning the trust record.

---

### Key decisions

- **D-48-C1 verdict DEFERRED** — fork divergence at `package_cmd.rs` + `profile_runtime.rs`
  (extended ArtifactType variants, different function signatures) made cherry-pick
  non-viable. D-20 manual-replay achieves equivalent security posture with fork-only
  invariants preserved (dual-layer path validation, `validate_path_within` post-write).
- **D-32-15 offline-verify invariant preserved** — `serde_json::Value` deserialization
  is schema-tolerant; `installed_path` field ignored in legacy bundles; fallback to
  `artifact_name` in upgraded reader path.
- **D-48-C3 mandatory regression test landed** — `tests/offline_verify_extended_trust_bundle.rs`
  (3 tests; all green): extended bundle parsing, legacy bundle backwards compat, path
  traversal rejection. Landing is unconditional (required regardless of upgrade/defer verdict).
- **Phase 47 DIVERGENCE-LEDGER.md stays as-shipped** — C9 resolution recorded in
  `48-08-DISPOSITION-RESOLUTION-DEFERRED.md` + this SUMMARY per D-48-C4 immutability.

---

### What was NOT absorbed and why

- `infer_artifact_type` removal: fork's version has `Hook` + `Script` variants not in
  upstream; deferred to a future cleanup commit.
- `update_lockfile` manifest-param refactor: requires migrating `infer_artifact_type`
  callers; deferred alongside `infer_artifact_type` removal.
- `install_manifest_artifact` path-construction refactor: fork's inline per-type match
  arms include `validate_path_within` defense-in-depth; both coexist safely.

---

### Files changed

- `crates/nono-cli/src/package_cmd.rs` — C9-01 + C9-02 manual-replay
- `crates/nono-cli/src/profile_runtime.rs` — C9-01 manual-replay (`validate_bundle_relative_path` + upgraded `verify_stored_bundles`)
- `crates/nono-cli/tests/offline_verify_extended_trust_bundle.rs` — D-48-C3 mandatory regression test (fork-authored; no upstream attribution)
