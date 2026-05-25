---
plan_id: 48-08
cluster: C9
upstream_sha_range: 5f1c9c73..8d774753
upstream_commit_count: 2
baseline_sha: 3f638dc6
disposition_input: fork-preserve-with-upgrade-authority (Phase 47 ledger immutable)
verdict: STAY D-20 manual-replay
verdict_suffix: DEFERRED
authored: 2026-05-25
---

# 48-08 Disposition Resolution: Cluster C9 (Package Manifest + Trust-Bundle Schema)

## § 1. Pre-flight Prerequisites

- **Plan 48-01 (Wave 0):** COMPLETE — merged onto `main` at merge commit `e0584f34` (recorded in STATE.md, Phase 47 ledger row C4 absorbed).
- **Plan 48-02 (Wave 1):** COMPLETE — merged via worktree at merge commit `2fab35ed` (STATE.md records summary 48-02-SUMMARY.md).
- **Plan 48-03 (Wave 1):** COMPLETE — merged via worktree at merge commit `ad2c99bd` (STATE.md records summary 48-03-SUMMARY.md).
- **Baseline SHA:** `3f638dc6` (Phase 46 post-merge baseline per D-48-E3; all CI lanes green at this SHA per 46-VERIFICATION.md).
- **Worktree base:** `8810d268` (Wave 2 start — merge of 48-07 C8 proxy cred format).
- **Both Wave 1 plans confirmed closed** before this artifact was produced (no code changes made).

C9 upstream shas are git-resolvable from the upstream remote:
```
5f1c9c73 OK (git cat-file -e 5f1c9c73^{commit})
8d774753 OK (git cat-file -e 8d774753^{commit})
```

## § 2. D-48-C1 Surface-Overlap Analysis (Per-File)

### Actual files touched by C9 upstream commits

The Phase 47 PLAN frontmatter (`files_modified`) listed `crates/nono/src/trust/policy.rs` and `crates/nono/src/manifest.rs` as expected targets. After executing `git show 5f1c9c73 --stat` and `git show 8d774753 --stat`, the ACTUAL files changed are:

**C9-01 (5f1c9c73) — `refactor(package): base installs on package manifest`:**
- `crates/nono-cli/src/package_cmd.rs` (+147 -54)
- `crates/nono-cli/src/profile_runtime.rs` (+59 -1)

**C9-02 (8d774753) — `feat(package): prevent artifact install path conflicts`:**
- `crates/nono-cli/src/package_cmd.rs` (+40 -16)

Neither commit touches `crates/nono/src/trust/policy.rs` or `crates/nono/src/manifest.rs`. The plan's `files_modified` metadata was based on the Phase 47 audit summary text ("trust-bundle schema extension") rather than the actual git diff. The schema extension is implemented within `package_cmd.rs` and `profile_runtime.rs`, not as new structs in library modules.

### 2a. `crates/nono-cli/src/package_cmd.rs` — Fork-side vs Upstream

**Upstream 5f1c9c73 changes:**
1. Adds `installed_artifact_relative_path(artifact: &ArtifactEntry) -> Result<String>` helper — centralizes manifest-to-install-path mapping (replaces scattered inline path construction).
2. Removes `infer_artifact_type(filename: &str) -> ArtifactType` — its callers now use manifest data directly.
3. Refactors `write_supporting_artifacts` to accept `manifest: &PackageManifest` parameter and use it to populate `installed_path` and `sha256_digest` in each `.nono-trust.bundle` entry.
4. Refactors `install_manifest_artifact` — removes per-ArtifactType path-construction inline code (now delegated to `installed_artifact_relative_path`).
5. Refactors `update_lockfile` — adds `manifest: &PackageManifest` parameter; switches from `infer_artifact_type` to `artifact.artifact_type` for lockfile entries.

**Fork HEAD state at `package_cmd.rs`:**
- `infer_artifact_type` STILL PRESENT (lines 1350-1362) — fork variant includes `ArtifactType::Hook` and `ArtifactType::Script` variants not present in upstream.
- `write_supporting_artifacts(staging_root, downloads)` still has OLD 2-param signature (no `manifest` param).
- `update_lockfile` still uses OLD signature (no `manifest` param); uses `infer_artifact_type` for artifact-type resolution.
- `.nono-trust.bundle` JSON entries still use old shape (`artifact` + `digest` + `bundle`); NO `installed_path` field written.
- `installed_artifact_relative_path` DOES NOT EXIST in the fork.
- `validate_manifest_install_paths` DOES NOT EXIST in the fork.

**Collision assessment for 5f1c9c73 on `package_cmd.rs`:**
SIGNIFICANT COLLISION — The upstream diff removes `infer_artifact_type` and refactors all its callers. The fork's `infer_artifact_type` has been extended with `ArtifactType::Hook` and `ArtifactType::Script` variants (lines 1356-1360) that are NOT in the upstream version, meaning the upstream deletion hunk would conflict on the variant set. Additionally, the function signature changes to `write_supporting_artifacts` and `update_lockfile` (adding `manifest` parameter) would conflict because the fork's call sites (`install_package` at line 890, `run_pull` at line 99) don't pass `manifest`. A direct cherry-pick would produce multiple conflict sites.

**Upstream 8d774753 changes on `package_cmd.rs`:**
1. Adds `validate_manifest_install_paths(manifest: &PackageManifest) -> Result<()>` at the start of `install_package`.
2. Improves error messages in `update_lockfile` path-conflict detection (adds both installed_path and artifact.path to error).
3. Extends `installed_artifact_relative_path` to guard reserved filenames (`package.json`, `.nono-trust.bundle`).

**Collision assessment for 8d774753 on `package_cmd.rs`:**
N/A for direct cherry-pick since 8d774753 builds on 5f1c9c73's refactored codebase. The fork doesn't have `installed_artifact_relative_path` yet, so 8d774753 cannot be cherry-picked without first having 5f1c9c73's full changes in place.

### 2b. `crates/nono-cli/src/profile_runtime.rs` — Fork-side vs Upstream

**Upstream 5f1c9c73 changes to `profile_runtime.rs`:**
1. In `verify_stored_bundles`: adds `installed_path` field extraction from bundle entry (with fallback to `artifact_name` if absent — using `.unwrap_or(artifact_name)`).
2. Extracts `expected_digest` from bundle entry (strict: errors if absent).
3. Uses `validate_bundle_relative_path(installed_path, artifact_name, pack_ref)` to derive the actual `artifact_path` (replaces `install_dir.join(artifact_name)`).
4. Adds `extract_all_subjects` call and digest-matching check (replaces `verify_bundle_subject_name`).
5. Adds `validate_bundle_relative_path(installed_path, artifact_name, pack_ref) -> Result<&Path>` function — validates the `installed_path` field from the bundle is safe (not empty, not absolute, no `..` or prefix components).

**Fork HEAD state at `profile_runtime.rs`:**
- `verify_stored_bundles` uses `install_dir.join(artifact_name)` — no `installed_path` extraction.
- No `validate_bundle_relative_path` function exists in the fork.
- Uses `verify_bundle_subject_name` (line 255) — NOT the upstream's `extract_all_subjects` + digest check.
- The `digest` field is NOT extracted from bundle entries.

**Collision assessment for 5f1c9c73 on `profile_runtime.rs`:**
PARTIAL COLLISION — The upstream hunks add NEW code around existing code. The `installed_path` extraction and `validate_bundle_relative_path` call are insertions into the `verify_stored_bundles` body. However, the replacement of `verify_bundle_subject_name` with `extract_all_subjects` + digest check IS a modification at the exact same source line (line 255 in the fork). This would produce a conflict. Additionally, the new `validate_bundle_relative_path` function added to profile_runtime.rs is a pure addition (no conflict), but the updated `artifact_path` derivation logic conflicts with the existing `let artifact_path = install_dir.join(artifact_name)` line.

## § 3. Schema Collision Check (`.nono-trust.bundle` field set)

**Current fork-side `.nono-trust.bundle` schema per entry** (written by `write_supporting_artifacts` in `package_cmd.rs`):
```json
{
  "artifact": "<filename>",
  "digest": "<sha256>",
  "bundle": { ... }
}
```

**Upstream C9 `.nono-trust.bundle` schema per entry** (added by 5f1c9c73):
```json
{
  "artifact": "<filename>",
  "installed_path": "<relative-path-within-install-dir>",
  "digest": "<sha256>",
  "bundle": { ... }
}
```

**Schema collision verdict: NO COLLISION on the schema itself** — upstream adds `installed_path` as an additional field. The fork already writes `artifact` + `digest` + `bundle`; the upstream adds `installed_path` between `artifact` and `digest`. Since the `.nono-trust.bundle` is deserialized via `serde_json::Value` (not a typed struct), additional fields are transparently preserved.

**Fork-side bundle reading code:**
`verify_stored_bundles` in `profile_runtime.rs` (line 203) calls `serde_json::from_str::<Vec<serde_json::Value>>()` — this is schema-tolerant; unknown fields are silently ignored. The fork's current code would correctly parse bundles produced by upgraded upstream consumers that include `installed_path`.

**Schema collision verdict: NO COLLISION (additive extension tolerated by `serde_json::Value` deserialization).**

## § 4. D-32-15 Verify-Is-Offline Invariant Check

**D-32-15 invariant definition** (from Phase 32 D-32-15; `keyless_offline_invariant.rs` codifies):
The offline verify path reads `trusted_root.json` via plain JSON deserialization (`TrustedRoot::from_file()`) — NOT TUF re-verification. The verify call chain is synchronous with no async/network I/O.

**Impact of C9 `installed_path` + `sha256_digest` on the offline verify path:**

1. `load_production_trusted_root()` → `TrustedRoot::from_file()` — this reads `trusted_root.json`, NOT `.nono-trust.bundle`. C9 changes do NOT touch this file or code path. **INVARIANT PRESERVED.**

2. `verify_stored_bundles()` in `profile_runtime.rs` reads `.nono-trust.bundle` via `serde_json::from_str::<Vec<serde_json::Value>>()`. C9 would add `installed_path` field to each entry; since the fork reads via `Value`, the extra field is ignored. If the fork DOES apply the upstream changes (upgrade path), the `installed_path` field becomes a required-with-fallback read: `entry.get("installed_path").and_then(|v| v.as_str()).unwrap_or(artifact_name)` — so it falls back gracefully on old bundles without `installed_path`. **INVARIANT PRESERVED in both upgrade and defer paths.**

3. `validate_bundle_relative_path` (upstream's new function) uses only `Path::new()`, path component iteration, and `path.is_absolute()` — all synchronous, no I/O. **DOES NOT INTRODUCE NETWORK I/O.**

**D-32-15 verify-is-offline invariant verdict: PRESERVED regardless of upgrade-or-defer decision.** The new schema fields do NOT break the offline verify path. The `serde_json::Value` deserialization approach is schema-tolerant by design.

## § 5. Trial Cherry-Pick Evidence

A trial cherry-pick was NOT executed (no git stash available in worktree mode per CLAUDE.md destructive-git-prohibition). The conflict analysis in § 2 is based on line-by-line diff inspection against the fork HEAD.

**Predicted conflicts for 5f1c9c73:**
- `package_cmd.rs`: ~4 conflict sites — `infer_artifact_type` deletion vs fork's extended variant set; `write_supporting_artifacts` parameter change vs call sites; `update_lockfile` parameter change vs call site in `run_pull`; `install_manifest_artifact` path-construction refactor vs fork's external_paths logic.
- `profile_runtime.rs`: 2 conflict sites — `artifact_path` derivation (old: `install_dir.join(artifact_name)` vs new: `validate_bundle_relative_path(...)`) and `verify_bundle_subject_name` vs `extract_all_subjects` + digest check.

**Overall cherry-pick prediction: WOULD FAIL — significant conflict count; manual resolution required for ~6 sites across 2 files.** Even if conflicts were manually resolved, the fork's `ArtifactType::Hook` and `ArtifactType::Script` variants (not in upstream) would need to be re-added to `infer_artifact_type` — but upstream is removing `infer_artifact_type` entirely, so the fork variants would need wiring into `installed_artifact_relative_path` instead.

## § 6. Surface-Semantics Divergence Evidence

**Fork's `infer_artifact_type` vs upstream's removal:**
The fork extended `infer_artifact_type` with `ArtifactType::Hook` and `ArtifactType::Script` variants (Phase 35/45 additions) beyond upstream's version. Upstream's 5f1c9c73 removes this function entirely, moving the type-to-path mapping into `installed_artifact_relative_path`. The D-20 manual-replay MUST add `ArtifactType::Hook` and `ArtifactType::Script` cases to the fork-side `installed_artifact_relative_path` equivalent to preserve the fork's extended type support.

**Fork's `validate_bundle_relative_path` (upstream) vs fork's absence:**
The fork does NOT have a `validate_bundle_relative_path` function. This is a **security-critical gap** per T-48-08-01 (attacker-controlled `installed_path` path traversal). The D-20 manual-replay MUST implement the equivalent defense-in-depth. The upstream's implementation uses path component iteration (`std::path::Component::Normal(_)` allow-list) — this is EQUIVALENT to or STRICTER than a `starts_with("..")` string check (per CLAUDE.md § Path Handling which mandates path-component comparison over string ops). The manual-replay will use the same component-iteration approach.

**Fork's `verify_bundle_subject_name` vs upstream's `extract_all_subjects` + digest check:**
The fork uses `verify_bundle_subject_name` which checks the bundle's subject matches the artifact filename. Upstream's 5f1c9c73 replaces this with `extract_all_subjects` + explicit digest comparison. The upstream approach is STRICTER: it verifies both the subject name AND the digest value from the bundle entry. The fork's `extract_all_subjects` function ALREADY EXISTS in `crates/nono/src/trust/bundle.rs` (line 963) and is re-exported through `mod.rs`. The D-20 manual-replay in `profile_runtime.rs` MUST upgrade to the stricter `extract_all_subjects` + digest check (per CLAUDE.md § Security — choose more restrictive option).

**Fork's `.nono-trust.bundle` producer vs upstream's extended producer:**
The fork's `write_supporting_artifacts` does NOT include `installed_path` in bundle entries. The D-20 manual-replay SHOULD add `installed_path` to bundle entries for audit-trail completeness — but this is not strictly required for the D-32-15 invariant (the reader falls back to `artifact_name` if `installed_path` is absent). The manual-replay will add it for forward compatibility.

## § 7. D-47-D2 Re-Export Scan

Re-export scan executed per CONTEXT.md `Claude's Discretion` bullet. Since the verdict is DEFER (D-20 manual-replay), this scan is N/A for gate purposes, but it was executed for completeness:

```
git show 5f1c9c73 -- crates/nono-cli/src/package_cmd.rs | grep '^+pub use\|^+pub mod\|^+extern crate'
→ (empty — no new pub re-exports)

git show 8d774753 -- crates/nono-cli/src/package_cmd.rs | grep '^+pub use\|^+pub mod\|^+extern crate'
→ (empty — no new pub re-exports)

git show 5f1c9c73 -- crates/nono-cli/src/profile_runtime.rs | grep '^+pub use\|^+pub mod\|^+extern crate'
→ (empty — no new pub re-exports)
```

**D-47-D2 re-export scan result: ZERO cross-cluster re-export deps.** Both C9 commits are purely internal to their respective modules. The `installed_artifact_relative_path` and `validate_bundle_relative_path` functions added by 5f1c9c73 are private (`fn`, not `pub fn`). No concern.

## § 8. Verdict

**VERDICT: STAY D-20 manual-replay**

**Rationale:**
1. The fork's `package_cmd.rs` has diverged substantially from upstream through Phase 35/45 additions (`ArtifactType::Hook`, `ArtifactType::Script`, extended `infer_artifact_type`, different `update_lockfile` signature) — a direct cherry-pick of 5f1c9c73 would produce ~6 conflict sites across 2 files, making verbatim D-19 cherry-pick non-viable without extensive manual resolution that would compromise D-19 trailer fidelity.

2. The security-critical improvements from C9 (path validation via component iteration, digest checking upgrade, `installed_path` in trust bundles) are individually well-defined and can be replayed fork-side using the fork's own existing helpers (`extract_all_subjects` already present in `bundle.rs`), producing equivalent or stricter security posture without the conflict burden.

3. The D-32-15 offline-verify invariant is preserved either way (§ 4 confirmed), so the upgrade criterion from D-48-C1 ("no D-32-15 offline-verify invariant collision") is satisfied for BOTH paths, but the schema-collision criterion ("no collision") is satisfied only with appropriate care in the manual-replay (which adds `installed_path` field to bundle entries while keeping `serde_json::Value` deserialization in the reader).

**This verdict satisfies REQ-UPST6-02 acceptance criterion #3 (D-20 manual-replay path).**

## § 9. Implications for Task 3

**C9-01: `5f1c9c73` → D-20 manual-replay** (fork-side commit mirroring upstream's manifest-driven install intent)

Fork-side implementation strategy:
- Add `installed_artifact_relative_path(artifact: &ArtifactEntry) -> Result<String>` private helper to `package_cmd.rs`, including fork's `ArtifactType::Hook` and `ArtifactType::Script` cases (NOT present in upstream).
- Extend `write_supporting_artifacts` to include `installed_path` in each bundle entry (using `installed_artifact_relative_path`).
- Add `validate_bundle_relative_path` to `profile_runtime.rs` (same implementation as upstream: component-iteration allow-list).
- Upgrade `verify_stored_bundles` to extract `installed_path` (fallback to `artifact_name`) and use `extract_all_subjects` + digest check (replacing `verify_bundle_subject_name`).
- Do NOT remove `infer_artifact_type` — the fork still uses it in `update_lockfile` for other code paths. The D-20 manual-replay adds `installed_artifact_relative_path` alongside `infer_artifact_type` (both coexist); a future cleanup commit can consolidate once the fork's extended ArtifactType variants are fully migrated.
- Trailer: `Upstream-replayed-from: 5f1c9c734b88d83f767bfac1f8eb09be44e8b793`
- Co-Authored-By: Luke Hinds <lukehinds@gmail.com>

**C9-02: `8d774753` → D-20 manual-replay** (fork-side commit adding path-conflict prevention)

Fork-side implementation strategy:
- Add `validate_manifest_install_paths(manifest: &PackageManifest) -> Result<()>` to `package_cmd.rs`.
- Extend `installed_artifact_relative_path` to guard reserved filenames (`package.json`, `.nono-trust.bundle`) — same logic as upstream.
- Call `validate_manifest_install_paths` at the start of `install_package`.
- Trailer: `Upstream-replayed-from: 8d774753c836f49fb48bffcc164fbfe73283ffa4`
- Co-Authored-By: Luke Hinds <lukehinds@gmail.com>

Both commits carry the 5-section D-20 body per Convention Pattern B:
- Upstream intent
- What was replayed
- What was NOT replayed and why
- Fork-only wiring preserved
- Upstream-replayed-from + Co-Authored-By + Signed-off-by

**Filename suffix at plan close:** Rename to `48-08-DISPOSITION-RESOLUTION-DEFERRED.md` per Claude's Discretion bullet in CONTEXT.md.
