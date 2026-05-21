---
phase: 49
plan: 02
subsystem: ci-release-pipeline
tags: [sigstore, trust-root, ci, release, packaging, poc-resilience]
requirements: [REQ-POC-TRUST-02]
dependency_graph:
  requires:
    - "crates/nono/tests/fixtures/trust-root-frozen.json (Phase 32 frozen fixture)"
    - ".github/workflows/release.yml::Generate checksums step"
    - ".github/workflows/release.yml::Create GitHub Release step"
  provides:
    - "Maintainer-side provenance chain: committed fixture -> CI artifact -> Release asset (byte-identical)"
    - "Release asset 'trusted_root.json' downloadable for `nono setup --from-file <PATH>` POC flow (Plan 49-01)"
    - "SHA256SUMS.txt coverage for trusted_root.json (full integrity gate)"
  affects:
    - "Phase 49 Plan 49-01 (--from-file flag) - now has a real release-asset URL to point at"
    - "Future tagged releases (v2.6.0 onward) - every release ships trusted_root.json"
tech_stack:
  added: []
  patterns:
    - "set -euo pipefail discipline on new bash blocks in CI"
    - "cp + sha256sum + equality-check byte-identity assertion pattern"
    - "Conditional sha256sum-append inside aggregation block (mirroring existing *.zip/*.msi pattern)"
key_files:
  created: []
  modified:
    - ".github/workflows/release.yml (+23 lines: set -euo pipefail header, byte-identity block, conditional sha256sum, files-glob entry)"
decisions:
  - "Folded all three insertions into a single atomic commit (chore(49-02): ship trusted_root.json as a release asset) per <commit_shape> in the plan"
  - "set -euo pipefail added at top of the Generate checksums step - upgrades existing block hygiene as a side-effect of the new code"
  - "Source path uses `../crates/nono/tests/fixtures/trust-root-frozen.json` (cwd-relative inside `artifacts/`) - composes correctly after `cd artifacts` per F-02-05"
  - "Destination path `trusted_root.json` is cwd-relative (inside `artifacts/`) for sha256sum; files-glob entry `artifacts/trusted_root.json` is repo-root-relative for softprops/action-gh-release"
metrics:
  duration_min: 8
  tasks_completed: 2
  files_modified: 1
  commits: 1
  completed_date: "2026-05-21"
---

# Phase 49 Plan 02: Release-asset bundling for trusted_root.json (REQ-POC-TRUST-02) Summary

## One-liner

Extended `.github/workflows/release.yml` to publish `trusted_root.json` as a release asset with a CI-asserted SHA-256 byte-identity gate between `crates/nono/tests/fixtures/trust-root-frozen.json` and the uploaded asset, closing the maintainer-side provenance chain for the Plan 49-01 `--from-file` POC flow.

## Outcome

`STRUCTURALLY-COMPLETE-PENDING-LIVE-RELEASE` — all source-side gates are met and validated locally; acceptance criteria (d) and (e) (live `gh release view <tag>` + downloaded-asset diff) intrinsically require a real tagged release per VALIDATION.md § "Manual-Only Verifications".

## What was built

Three minimal-diff insertions inside the existing `release` job of `.github/workflows/release.yml`:

1. **Byte-identity assert** (inside `Generate checksums` step, between the `find -name "*.deb"` line and the `sha256sum *.tar.gz` line):

   ```bash
   SRC=../crates/nono/tests/fixtures/trust-root-frozen.json
   DST=trusted_root.json
   cp "$SRC" "$DST"
   SRC_SHA=$(sha256sum "$SRC" | cut -d' ' -f1)
   DST_SHA=$(sha256sum "$DST" | cut -d' ' -f1)
   if [ "$SRC_SHA" != "$DST_SHA" ]; then
     echo "ERROR: trusted_root.json byte-identity assert failed" >&2
     echo "  src ($SRC): $SRC_SHA" >&2
     echo "  dst ($DST): $DST_SHA" >&2
     exit 1
   fi
   echo "trusted_root.json byte-identity verified: $SRC_SHA"
   ```

2. **SHA256SUMS aggregation entry** (mirrors the existing `*.zip` / `*.msi` / `*.exe` pattern, conditional in case the asset is somehow missing):

   ```bash
   if ls trusted_root.json >/dev/null 2>&1; then
     sha256sum trusted_root.json >> SHA256SUMS.txt
   fi
   ```

3. **`files:` glob entry** in the `Create GitHub Release` step:

   ```yaml
   artifacts/trusted_root.json
   ```

4. **Side-effect hygiene fix:** `set -euo pipefail` added at the top of the `Generate checksums` step's `run:` block (F-02-04 mitigation). The previous block did NOT have this — the new logic mandates it (any `cut`-pipe failure would otherwise mask a real hash mismatch), and the upgrade carries the existing aggregation block along for the ride at zero risk.

## Verification

### Automated gates (executed in this worktree)

| Gate                                     | Outcome   | Evidence                                                                                                                       |
| ---------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------ |
| `python yaml.safe_load` of release.yml   | PASS      | `yaml valid` printed                                                                                                            |
| Grep: `set -euo pipefail`                | PASS      | 1 match at line 310                                                                                                             |
| Grep: `byte-identity verified`           | PASS      | 1 match at line 333                                                                                                             |
| Grep: `byte-identity assert failed`      | PASS      | 1 match at line 328                                                                                                             |
| Grep: `sha256sum trusted_root.json >> SHA256SUMS.txt` | PASS | 1 match at line 346                                                                                                |
| Grep: `^            artifacts/trusted_root.json$` (12-space) | PASS | 1 match at line 362                                                                                                |
| Grep count: `trusted_root.json` mentions | PASS      | 7 matches (>= 5 required)                                                                                                       |
| `git diff --stat`                        | PASS      | only `.github/workflows/release.yml` modified, +23 lines                                                                       |
| Positive local dry-run                   | PASS      | SHA `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66` verified on actual frozen fixture                       |
| Negative local dry-run (tampered DST)    | PASS      | `EXPECTED FAIL (tampered dst): src=6494e21e… dst=d8b268ff…` — assert correctly rejected; exit code 1; gate proven to have teeth |

### PARTIAL gates (tooling not installed on worktree host)

| Gate        | Status              | Substitute Evidence                                                       |
| ----------- | ------------------- | ------------------------------------------------------------------------- |
| `yamllint`  | PARTIAL (not installed) | `python yaml.safe_load` is the explicit floor per plan; passed.        |
| `shellcheck` | PARTIAL (not installed) | Extracted bash block is 40 lines, uses only `set -euo pipefail` + `cp`/`sha256sum`/`cut`/`if`/`echo`/`exit` (all POSIX-safe primitives); positive + negative dry-runs structurally exercise the same logic in the same shell idiom and both behave as intended. |

The plan explicitly permits both PARTIAL outcomes when tooling is unavailable; recorded here per `<verification_strategy>` instruction.

### Frozen fixture state

- Path: `crates/nono/tests/fixtures/trust-root-frozen.json`
- Size: 6787 bytes
- Lines: 126
- SHA-256: `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`

### Live-release verification (STRUCTURALLY-COMPLETE-PENDING-LIVE-RELEASE)

Per VALIDATION.md § "Manual-Only Verifications", REQ-POC-TRUST-02 acceptance criteria (d) and (e) require a real tagged release to verify. On the next tagged release (e.g., `v2.6.0`):

```bash
gh release view <tag> --json assets | jq '.assets[].name'   # must list trusted_root.json
gh release download <tag> -p trusted_root.json
diff trusted_root.json crates/nono/tests/fixtures/trust-root-frozen.json   # must exit 0
gh release download <tag> -p SHA256SUMS.txt
grep trusted_root.json SHA256SUMS.txt                       # must exit 0
```

These three Manual-Only verifications close the chain end-to-end; this plan's structural commitment guarantees they will succeed by construction (the CI gate exits non-zero if the bytes diverge, so a tagged release with this commit on the release branch cannot ship a non-byte-identical asset).

## Failure mode coverage

| ID       | Failure Mode                                  | Mitigation Implemented                                                                                                                                                            |
| -------- | --------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| F-02-01  | Byte-identity drift                           | `SRC_SHA`/`DST_SHA` equality check with non-zero exit on mismatch (line 327); positive + negative local dry-runs validated locally.                                              |
| F-02-02  | Release-asset omission                        | `artifacts/trusted_root.json` line in the `softprops/action-gh-release` `files:` glob (line 362); covered post-release by `gh release view --json assets`.                          |
| F-02-03  | SHA256SUMS omission                           | Conditional `sha256sum trusted_root.json >> SHA256SUMS.txt` (line 346); covered post-release by `grep trusted_root.json SHA256SUMS.txt`.                                          |
| F-02-04  | CI silent-pass (`cut`-pipe failure)           | `set -euo pipefail` at top of step (line 310). Any internal pipe or unbound-var failure now exits non-zero instead of masking a real mismatch.                                    |
| F-02-05  | Working-directory mismatch                    | New block folded INSIDE the existing `cd artifacts` scope; source uses `../crates/nono/tests/fixtures/trust-root-frozen.json` (one level up from `artifacts/`); destination is cwd-relative. Manual diff review confirmed paths compose. |

## Threat coverage

All four STRIDE entries in `<threat_model>` mitigated structurally:

- **T-49-04** (maintainer-side leak) — mitigated by F-02-01 byte-identity assert.
- **T-49-04b** (release-asset omission) — mitigated by F-02-02 files-glob entry.
- **T-49-04c** (hash omission from SHA256SUMS.txt) — mitigated by F-02-03 conditional `sha256sum`.
- **T-49-06** (CI silent-pass) — mitigated by F-02-04 `set -euo pipefail`.
- **T-49-07** (working-dir mismatch) — mitigated by F-02-05 in-scope insertion.

## Deviations from Plan

None — plan executed exactly as written. Single atomic commit per `<commit_shape>`; all task-1 grep gates and task-2 dry-runs passed; PARTIAL outcomes on `yamllint` and `shellcheck` were explicitly permitted by the plan when those tools are unavailable.

## Files modified

| File                              | Change                          | Lines |
| --------------------------------- | ------------------------------- | ----- |
| `.github/workflows/release.yml`   | +set-euo pipefail / +byte-identity block / +conditional sha256sum / +files-glob entry | +23  |

## Commit

| Commit     | Subject                                                                  |
| ---------- | ------------------------------------------------------------------------ |
| `c3e1bf92` | `chore(49-02): ship trusted_root.json as a release asset` (single atomic) |

DCO sign-off present (`Signed-off-by: Oscar Mack Jr. <oscar.mack.jr@gmail.com>`).

## Threat Flags

None — this plan introduces no new security-relevant surface beyond what the plan's `<threat_model>` already enumerated. The new CI step is contained within the existing `release` job, runs only at tag-push, has no network primitives beyond what `softprops/action-gh-release` already uses, and emits no new file or trust-boundary crossings.

## Self-Check: PASSED

- File exists: `.github/workflows/release.yml` — FOUND
- File exists: `.planning/phases/49-sigstore-trust-root-poc-resilience-from-file-flag-release-as/49-02-SUMMARY.md` — FOUND (this file)
- Commit `c3e1bf92` exists in `git log --oneline` — FOUND
- Frozen fixture exists: `crates/nono/tests/fixtures/trust-root-frozen.json` — FOUND (6787 bytes, SHA-256 `6494e21e…`)
