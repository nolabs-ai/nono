---
phase: 50
plan: 03
subsystem: nono-cli/trust-refresh
tags:
  - sigstore
  - tuf
  - trust-root
  - corp-network
  - call-site-swap
  - wave-2
requires:
  - crate::trust_refresh::refresh_production_trusted_root (Plan 50-02 full impl)
  - sigstore-trust-root 0.7.0 direct edge (Plan 50-01)
  - tough 0.22.0 direct edge (Plan 50-01)
  - ureq 3.3.0 + platform-verifier feature (pre-Phase-50)
provides:
  - "Production wiring: `nono setup --refresh-trust-root` now drives the nono-local TUF chain-walk over a ureq + platform-verifier HTTP transport that consults the OS root store"
  - "SPEC Req 1 acceptance (R-50-02-scoped): `grep -nE 'TrustedRoot::production\\(\\)' crates/nono-cli/src/setup.rs` returns 0 matches"
affects:
  - crates/nono-cli/src/setup.rs (refresh_trust_root_step body — 6 line edit: 1-line block_on arg swap + 5-line comment rewrite that net-replaces a 3-line comment)
  - crates/nono-cli/src/trust_refresh.rs (drop Wave-0 #[allow(dead_code)] + 3-line scaffolding comment)
tech-stack:
  added: []
  patterns:
    - "minimal call-site swap: pre-existing async pipeline re-routed through new local function without touching cache contract"
    - "preserved-verbatim discipline: cache-dir setup, header print, tokio runtime, serialization, fs::write, success print, user-visible error string ALL untouched"
key-files:
  modified:
    - crates/nono-cli/src/setup.rs
    - crates/nono-cli/src/trust_refresh.rs
decisions:
  - "Removed `#[allow(dead_code)]` on `refresh_production_trusted_root` in the same commit (Rule 2 — Plan 50-01 / 50-02 SUMMARYs explicitly contract Plan 50-03 to do this once the call site is wired). Leaving it would be a misleading lint-suppression on now-live code."
  - "Used `url.as_str()`-style explicit literal preservation: the user-visible error string 'Failed to fetch Sigstore trusted root from https://tuf-repo-cdn.sigstore.dev:' is UAT pass criteria (SPEC Req 6) and PATTERNS.md §Error Handling exception — kept verbatim."
  - "Did NOT touch the tokio one-shot runtime (RESEARCH.md A4 correction to CONTEXT.md): `tough::RepositoryLoader::load`, `Repository::read_target`, and `IntoVec::into_vec` are ALL async, so the runtime is functionally required."
metrics:
  tasks_completed: 1
  files_changed: 2
  commits: 1
  completed_date: 2026-05-22
---

# Phase 50 Plan 03: Wave 2 call-site swap — Summary

**One-liner:** Swapped `rt.block_on(nono::trust::TrustedRoot::production())` to `rt.block_on(crate::trust_refresh::refresh_production_trusted_root())` inside `SetupRunner::refresh_trust_root_step`, wiring the Wave 1 OS-root-store-aware TUF chain-walk into the user-facing `nono setup --refresh-trust-root` flow while preserving the cache contract, UX, and async runtime verbatim.

## Tasks Completed

| # | Task | Commit | Files |
|---|------|--------|-------|
| 1 | Swap the rt.block_on() target in refresh_trust_root_step | `7ab44073` | `crates/nono-cli/src/setup.rs`, `crates/nono-cli/src/trust_refresh.rs` |

## Diff

`git diff` between the pre-edit baseline (HEAD~1 = `26277c36`) and the post-edit commit (`7ab44073`):

```diff
diff --git a/crates/nono-cli/src/setup.rs b/crates/nono-cli/src/setup.rs
index a2f522d6..c83a0f90 100644
--- a/crates/nono-cli/src/setup.rs
+++ b/crates/nono-cli/src/setup.rs
@@ -838,15 +838,20 @@ impl SetupRunner {
         );

         // ONE-SHOT tokio runtime — the rest of `nono setup` is sync.
-        // TrustedRoot::production() runs full TUF verification (signature
-        // threshold 3, root-of-trust pinned in sigstore-rs) before returning.
-        // The bytes we persist are post-verification per T-32-02-01.
+        // Phase 50: tough::RepositoryLoader::load, Repository::read_target,
+        // and IntoVec::into_vec are ALL async (tough-0.22.0/src/lib.rs:206,
+        // :458; transport.rs:21-36). The runtime is PRESERVED; the only
+        // change is the rt.block_on() argument. Signature threshold + TUF
+        // chain walk now happens inside crate::trust_refresh, which uses
+        // a ureq + platform-verifier transport that consults the OS root
+        // store (fixes corp-network failure documented in
+        // .planning/debug/resolved/sigstore-tuf-fetch-transport.md).
         let rt = tokio::runtime::Builder::new_current_thread()
             .enable_all()
             .build()
             .map_err(|e| NonoError::Setup(format!("tokio runtime: {e}")))?;
         let trusted_root = rt
-            .block_on(nono::trust::TrustedRoot::production())
+            .block_on(crate::trust_refresh::refresh_production_trusted_root())
             .map_err(|e| {
                 NonoError::Setup(format!(
                     "Failed to fetch Sigstore trusted root from \

diff --git a/crates/nono-cli/src/trust_refresh.rs b/crates/nono-cli/src/trust_refresh.rs
index caf30025..aea14521 100644
--- a/crates/nono-cli/src/trust_refresh.rs
+++ b/crates/nono-cli/src/trust_refresh.rs
@@ -212,10 +212,6 @@ async fn do_refresh_after_datastore_create(
 /// cleanup of the TUF datastore at `<nono_home>/.nono/trust-root/tuf-cache/`
 /// is performed on ANY failure path after `create_dir_all` succeeds
 /// (D-49-B2 / D-50-07 — broadened per Codex R-50-05).
-// Phase 50 Wave 1: this function is still not invoked from any production
-// code path; Plan 50-03 swaps `setup.rs::refresh_trust_root_step` to call
-// it. The `#[allow(dead_code)]` is removed at that point.
-#[allow(dead_code)]
 pub async fn refresh_production_trusted_root() -> Result<TrustedRoot> {
     // 1. URL setup (mirror sigstore-trust-root tuf.rs:350-354).
     let base_url = Url::parse(DEFAULT_TUF_URL)
```

`setup.rs` net: 9 insertions, 4 deletions inside `refresh_trust_root_step`. `trust_refresh.rs` net: 0 insertions, 4 deletions (attribute + comment block removed). Grand total: 9 insertions, 8 deletions across the 2 files — matches the plan's expected "~9-line diff" budget.

## Verification

| Check | Expected | Actual | Pass |
|-------|----------|--------|------|
| `grep -nE 'TrustedRoot::production\(\)' crates/nono-cli/src/setup.rs` (Req 1 acceptance, R-50-02-scoped) | 0 matches (grep exit 1) | 0 matches (grep exit 1) | ✓ |
| `grep -rcn 'crate::trust_refresh::refresh_production_trusted_root' crates/nono-cli/src/setup.rs` | 1 | 1 | ✓ |
| `grep -rcn 'trust_refresh::refresh_production_trusted_root' crates/nono-cli/src/` (tree-wide single invocation) | exactly 1 file with count ≥ 1, all others 0 | only `setup.rs:1`, all other files 0 (90 files surveyed) | ✓ |
| `grep -cE 'tokio::runtime::Builder::new_current_thread\(\)' crates/nono-cli/src/setup.rs` (RUNTIME PRESERVED per RESEARCH.md A4) | ≥ 1 | 1 | ✓ |
| `grep -cE 'serde_json::to_string_pretty\(&trusted_root\)' crates/nono-cli/src/setup.rs` (Req 4 byte-identical cache) | ≥ 1 | 1 | ✓ |
| `grep -cE 'std::fs::write\(&cache_path' crates/nono-cli/src/setup.rs` (cache write preserved) | ≥ 1 | 1 | ✓ |
| `grep -cE 'Failed to fetch Sigstore trusted root from' crates/nono-cli/src/setup.rs` (UAT-visible error preserved) | ≥ 1 | 1 | ✓ |
| `grep -cE '\[\{\}/\{\}\] Refreshing Sigstore trusted root' crates/nono-cli/src/setup.rs` (header preserved) | ≥ 1 | 1 | ✓ |
| `grep -cE 'fixes corp-network failure documented in' crates/nono-cli/src/setup.rs` (new explanatory comment present) | ≥ 1 | 1 | ✓ |
| `cargo build -p nono-cli` (host triple x86_64-pc-windows-msvc) | exit 0 | exit 0 (15.06s after 3m 16s cold-build of dep graph) | ✓ |
| `cargo clippy -p nono-cli --no-deps -- -D warnings -D clippy::unwrap_used` (host triple) | exit 0 | exit 0 (4.49s incremental; 2m 03s after full re-check) | ✓ |
| Tree-wide informational grep `grep -rn 'TrustedRoot::production()' crates/nono-cli/src/` | 0 matches (Plans 01/02 hygiene) | 0 matches | ✓ |

### Tree-wide informational grep result

`grep -rn 'TrustedRoot::production()' crates/nono-cli/src/` returns **zero matches anywhere in the nono-cli source tree**. This confirms the R-50-02 hygiene contract from Plans 50-01 + 50-02 held perfectly: no module doc, no comment, no test fixture, no executable code line in nono-cli contains the literal `TrustedRoot::production()` string after this plan lands. The setup.rs-scoped acceptance grep in SPEC Req 1 (line 83) IS satisfied; the broader-tree informational grep also returns 0 (i.e. the planner's worry that R-50-02 could not be satisfied by a broad grep is now empirically moot — both scopings would have passed).

### Cross-target clippy (D-50-13 HARD pass)

**NOT attempted in Plan 03.** Plan 01 surfaced BLOCKER-50-01 (Windows dev host lacks `x86_64-linux-gnu-gcc` and macOS SDK / `cc` cross-toolchains needed by `cc-rs` for aws-lc-rs/ring). Plan 03 inherits the same constraint unchanged; Plan 05 owns the resolution path (install cross-toolchains locally, OR revise D-50-13 from HARD to PARTIAL per the R-50-04 reopen path).

### Manual smoke test

**NOT attempted in Plan 03.** Per the plan's `<verification>` block, the manual smoke test `cargo run -p nono-cli -- setup --refresh-trust-root` is documented as "optional pre-Plan-04" and the automated end-to-end coverage is deferred to Plan 04's hermetic tests and Plan 05's corp-network HUMAN-UAT. The compile-time wiring proof (build + strict clippy on the host triple) is sufficient evidence for Plan 03's scope; live network behavior is exactly what Plan 05 will measure.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 — Critical functionality] Remove `#[allow(dead_code)]` on `refresh_production_trusted_root`**

- **Found during:** Task 1 (pre-commit clippy verification)
- **Issue:** The plan's Task 1 `<action>` block focuses on the two `setup.rs` substitutions and does not explicitly mention the `#[allow(dead_code)]` attribute on `crate::trust_refresh::refresh_production_trusted_root`. However:
  - Plan 50-01 SUMMARY Deviations §2 explicitly states: "Plan 03's deliverable removes it once the call site is wired."
  - Plan 50-02 SUMMARY Orchestrator Notes §2 explicitly states: "Plan 50-03 can swap... and remove the `#[allow(dead_code)]` attribute in the same commit."
  - Leaving the attribute in place on a now-live function is a misleading lint-suppression. While `rustc` doesn't yet warn about a redundant `allow`, the attribute now claims the function is dead code — a code-quality / clarity regression.
- **Fix:** Removed the `#[allow(dead_code)]` attribute and the 3-line explanatory comment that referenced its eventual removal. The function is now live; the attribute is no longer warranted.
- **Files modified:** `crates/nono-cli/src/trust_refresh.rs`
- **Commit:** `7ab44073` (same commit as the setup.rs swap, to keep wiring + cleanup atomic)

### Threat-model coverage check

All threat-register dispositions from the plan's `<threat_model>` were honored:

- **T-50-03-01** (Tampering — async runtime mis-handling): MITIGATED. The `tokio::runtime::Builder::new_current_thread()` block at setup.rs:844-848 is preserved verbatim; the new explanatory comment cites RESEARCH.md A4 + tough-0.22.0 source lines.
- **T-50-03-02** (Tampering — cache contract regression): MITIGATED. Acceptance greps confirm both `serde_json::to_string_pretty(&trusted_root)` AND `std::fs::write(&cache_path` are still present unchanged.
- **T-50-03-03** (Repudiation/Spoofing — user-visible error message drift): MITIGATED. Acceptance grep `Failed to fetch Sigstore trusted root from` returns 1 (verbatim string preserved).
- **T-50-03-04** (Spoofing — symbol resolution): MITIGATED. `cargo build -p nono-cli` exit 0 is the compile-time proof; the path `crate::trust_refresh::refresh_production_trusted_root` resolves to the Plan 50-02 implementation.
- **T-50-03-05** (Spoofing — self-defeating acceptance grep R-50-02): MITIGATED. The setup.rs-scoped grep is the executable-code check; tree-wide grep ALSO returns 0 (Plans 01/02 hygiene held), so both interpretations of SPEC Acceptance line 83 are empirically satisfied.

## Corp-network failure mode: structural resolution

After this plan lands, the failure documented in `.planning/debug/resolved/sigstore-tuf-fetch-transport.md` is **structurally resolved** for the cohort of Windows users whose enterprise CA is in the Windows root store (Crypt32):

- **Before Phase 50:** `refresh_trust_root_step` → `nono::trust::TrustedRoot::production()` → sigstore-trust-root 0.7.0 → tough 0.22.0 → reqwest 0.12.28 (with hyper-rustls 0.27.9 + webpki-roots Mozilla bundle). The TLS handshake against `tuf-repo-cdn.sigstore.dev` reaches the corporate TLS-inspecting proxy, which presents a certificate signed by the enterprise CA; webpki-roots does not know about that CA; `error sending request for url` follows.
- **After Phase 50:** `refresh_trust_root_step` → `crate::trust_refresh::refresh_production_trusted_root` → `tough::RepositoryLoader` with nono's `UreqTransport(ureq::Agent)` configured with `RootCerts::PlatformVerifier`. The TLS handshake reaches the same proxy, but the trust validation routes through `rustls-platform-verifier` → Crypt32 → `HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT` where the enterprise CA lives. Validation succeeds; the chain walk proceeds; the cache file lands.

Cross-platform note (D-21 invariance, SPEC.md Boundaries): on Linux the same code path goes through `rustls-platform-verifier` → openssl-probe → `/etc/ssl/certs/ca-certificates.crt`. On macOS it goes through `rustls-platform-verifier` → Security framework. The Phase 50 change is functionally a no-op on those platforms (no enterprise CA gap), but the file diff is non-zero on every OS (the swap touches a cross-platform file, not a `#[cfg(target_os = "windows")]` branch — D-50-11 single-code-path design). Linux/macOS behavior must not regress; that empirical check is Plan 04 (hermetic tests across OS) and Plan 05's CI lanes.

**Empirical confirmation deferred to Plan 50-05 HUMAN-UAT.** The corp-network user from `sigstore-tuf-fetch-transport.md` re-running `nono setup --refresh-trust-root` against a v0.53.x+ binary is the final pass criterion. Plan 03's contribution is the compile-time + lint-time proof that the new code path is reachable from the CLI surface.

## Threat Flags

No new threat-model surface introduced beyond what the plan's `<threat_model>` enumerates. The call site swap moves an existing async TUF + HTTP egress from sigstore-rs's reqwest+webpki-roots client to nono's ureq+platform-verifier client — same egress destination, same payload contract, broader trust anchor set. No new network endpoint, no new auth path, no new file-access pattern, no new schema-at-trust-boundary surface.

## Known Stubs

None. The function `refresh_production_trusted_root` is fully implemented from Plan 50-02; this plan only wires the call site. There are zero hardcoded empty values, placeholder strings, or "TODO" markers introduced. The previously-warranted `#[allow(dead_code)]` attribute is removed in the same commit.

## TDD Gate Compliance

This plan is `type: execute` (not `type: tdd`), so the RED/GREEN/REFACTOR gate sequence does not apply. Hermetic test coverage for the new chain-walk is deferred to Plan 50-04 (per SPEC Req 5). Plan 03's verification is build + clippy + acceptance greps; live behavior is Plan 05's HUMAN-UAT.

## Self-Check

- File `crates/nono-cli/src/setup.rs` modified (refresh_trust_root_step body): FOUND
- File `crates/nono-cli/src/trust_refresh.rs` modified (dead_code attribute + scaffolding comment removed): FOUND
- Commit `7ab44073 feat(50-03): swap refresh_trust_root_step to crate::trust_refresh`: FOUND (`git log --oneline -3` lists it as HEAD on `worktree-agent-a5a3e7589ea8d16c5`)
- SPEC Req 1 acceptance grep (R-50-02-scoped, setup.rs-only): 0 matches — VERIFIED
- New call grep (setup.rs-scoped): exactly 1 match — VERIFIED
- Tree-wide invocation grep (`crates/nono-cli/src/`): exactly 1 file (setup.rs) with count 1; all 89 other files count 0 — VERIFIED
- Tokio runtime preserved (RESEARCH.md A4): VERIFIED
- Cache contract preserved (`serde_json::to_string_pretty` + `std::fs::write`): VERIFIED
- User-visible error string preserved (UAT pass criteria): VERIFIED
- Header print preserved: VERIFIED
- New explanatory comment present (cites corp-network failure doc): VERIFIED
- Tree-wide informational grep on `TrustedRoot::production()`: 0 matches — VERIFIED
- `cargo build -p nono-cli` (host triple): exit 0 — VERIFIED
- `cargo clippy -p nono-cli --no-deps -- -D warnings -D clippy::unwrap_used` (host triple): exit 0 — VERIFIED

## Self-Check: PASSED

## Notes for Plan 50-04 / 50-05

1. **The call site is now live.** Hermetic test coverage (SPEC Req 5) can be authored against the real `refresh_production_trusted_root` instead of a stub. The function signature `pub async fn refresh_production_trusted_root() -> nono::Result<nono::trust::TrustedRoot>` is stable and matches Plan 50-04's expected test entry point.
2. **BLOCKER-50-01 carries forward unchanged.** Plan 05 still needs to resolve the cross-target `cc-rs` toolchain gap on the Windows dev host (or revise D-50-13 from HARD to PARTIAL).
3. **The corp-network failure mode is structurally resolved** for users with their enterprise CA in the Windows root store. Plan 05's HUMAN-UAT against the original POC user is the final empirical confirmation.
4. **Cross-platform diff posture:** `setup.rs` and `trust_refresh.rs` are NOT `#[cfg(target_os = "windows")]`-gated; they're shared code. Linux/macOS behavior should be equivalent (rustls-platform-verifier consults the appropriate native trust store on each OS). The empty-Linux/empty-macOS-diff guarantee from D-21 applies to OS-specific files only, not to cross-platform files like these.
