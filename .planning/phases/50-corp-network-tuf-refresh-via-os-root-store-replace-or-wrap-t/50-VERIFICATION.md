---
phase: 50-corp-network-tuf-refresh-via-os-root-store-replace-or-wrap-t
verified: 2026-05-22T00:00:00Z
status: human_needed
score: 6/6 must-haves verified (Req 6 awaits POC-user UAT run)
overrides_applied: 0
re_verification:
  previous_status: none
  previous_score: n/a
  gaps_closed: []
  gaps_remaining: []
  regressions: []
human_verification:
  - test: "Run `nono setup --refresh-trust-root` on a Windows host behind a TLS-inspecting corporate proxy whose interceptor CA is in the Windows root store"
    expected: "Step [3/5] exits 0; <nono_home>/.nono/trust-root/trusted_root.json is written and non-empty; stderr contains ZERO `error sending request for url` errors"
    why_human: "SPEC Req 6 acceptance is binary and dispositive — only a real corp-network host can verify that ureq + rustls-platform-verifier actually consults the Windows Crypt32 root store as advertised. Hermetic unit tests deliberately do not exercise a real TLS handshake (D-50-09)."
---

# Phase 50: Corp-network TUF refresh via OS root store Verification Report

**Phase Goal:** `nono setup --refresh-trust-root` succeeds on a Windows host behind a TLS-inspecting corporate proxy (whose interceptor CA is in the Windows root store but not in the Mozilla webpki-roots bundle), by replacing the single `sigstore-rs TrustedRoot::production()` call with a nono-local TUF chain-walk that uses an HTTP client (ureq + platform-verifier) consulting the OS certificate store.

**Verified:** 2026-05-22
**Status:** human_needed (all automated checks PASS; SPEC Req 6 awaits POC-user UAT run)
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| #   | Truth | Status | Evidence |
| --- | ----- | ------ | -------- |
| 1   | Single `TrustedRoot::production()` call site in `setup.rs::refresh_trust_root_step` replaced with `crate::trust_refresh::refresh_production_trusted_root()` (SPEC Req 1) | VERIFIED | `crates/nono-cli/src/setup.rs:854` reads `.block_on(crate::trust_refresh::refresh_production_trusted_root())`; setup.rs-scoped grep for `TrustedRoot::production()` returns 0 matches; tree-wide returns 1 (only in a Test 4 doc-comment inside `trust_refresh.rs` describing the baseline; not executable code) |
| 2   | `crates/nono-cli/src/trust_refresh.rs` contains a nono-local TUF chain-walk using `tough::RepositoryLoader` + `ureq::Agent` with `RootCerts::PlatformVerifier` so OS root store is consulted (SPEC Req 2 + Req 3) | VERIFIED | trust_refresh.rs:73-133 (`impl Transport for UreqTransport`), :143-154 (`build_corp_friendly_agent` with `RootCerts::PlatformVerifier`), :167-202 (`do_refresh_after_datastore_create_with_root` calling `RepositoryLoader::new(&embedded_root, ...).load().await`); zero `reqwest::Client::builder` in file; zero hand-rolled `verify_role`/`Signed<Root>` |
| 3   | Chain-walk produces `TrustedRoot` value structurally equivalent to upstream; D-50-07 cleanup wipes partial cache directory on ANY post-`create_dir_all` failure (SPEC Req 4 + Codex R-50-05) | VERIFIED | trust_refresh.rs:200 parses via `TrustedRoot::from_json(json)` (same parser cache reader uses); :221-262 `refresh_trusted_root_with_transport` captures the inner-helper Result once and runs `let _ = std::fs::remove_dir_all(&datastore_for_cleanup);` once on Err — single broadened cleanup path (grep returns exactly 1 occurrence in src/) |
| 4   | ≥4 hermetic tests exist (happy, bad-sig, malformed, byte-identical baseline, from_file round-trip, env-seam) and pass cross-OS (SPEC Req 5) | VERIFIED | 6 `#[tokio::test]` functions present at trust_refresh.rs:480-730. `cargo test -p nono-cli --bin nono trust_refresh::tests` exits 0 with `test result: ok. 6 passed; 0 failed` on host triple (Windows x86_64) at HEAD (verified during this verification pass) |
| 5   | HUMAN-UAT scenario for corp-network proof exists with R-50-06 (proxy/PAC) and R-50-10 (403 obscurity) residual-risk sections (SPEC Req 6 — artifact half) | VERIFIED | `50-HUMAN-UAT.md` exists with 1 substantive `## Scenario 1` heading + recording-template heading; contains "TLS-inspecting corporate proxy" (2 matches); ### Residual risks section enumerates: 1) PAC/WPAD/WinHTTP proxy discovery, 2) Basic/NTLM/Kerberos proxy auth, 3) 403→FileNotFound diagnostic obscurity, 4) CA missing from Windows root store |
| 6   | Cross-target clippy HARD pass on x86_64-unknown-linux-gnu (D-50-13 + Codex R-50-04); x86_64-apple-darwin lane marked PARTIAL with user sign-off | VERIFIED (split-state) | Linux lane: `cross clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used` exits 0 at HEAD `60214a28` (recorded in 50-05-SUMMARY.md with proof log path `/tmp/cross-clippy-linux-worktree.log`); macOS lane: PARTIAL per `.planning/templates/cross-target-verify-checklist.md` with explicit user-acknowledged sign-off 2026-05-22 |

**Score:** 6/6 truths verified (all automated checks PASS; SPEC Req 6 binary-pass criterion awaits POC-user UAT run per D-50-09)

### Required Artifacts

| Artifact | Expected | Status | Details |
| -------- | -------- | ------ | ------- |
| `crates/nono-cli/src/trust_refresh.rs` | UreqTransport + TUF chain-walk + 6 hermetic tests; min 320 lines | VERIFIED | 732 lines; UreqTransport impl Transport (lines 73-133), build_corp_friendly_agent (143-154), do_refresh_after_datastore_create_with_root (167-202), refresh_trusted_root_with_transport pub(crate) seam (221-262), refresh_production_trusted_root public wrapper (281-330), #[cfg(test)] mod tests with 6 tests (346-731) |
| `crates/nono-cli/src/setup.rs` | `refresh_trust_root_step` block_on swapped to `crate::trust_refresh::refresh_production_trusted_root()`; tokio runtime + cache write + UX preserved | VERIFIED | Line 854 `.block_on(crate::trust_refresh::refresh_production_trusted_root())`; tokio runtime block at 849-852 preserved; `serde_json::to_string_pretty(&trusted_root)` + `std::fs::write(&cache_path, &json)` cache contract preserved; user-visible error string "Failed to fetch Sigstore trusted root from https://tuf-repo-cdn.sigstore.dev:" preserved |
| `crates/nono-cli/src/main.rs` | `mod trust_refresh;` declaration | VERIFIED | Line 94 between `mod trust_keystore;` and `mod trust_scan;` (alphabetical), no cfg gate |
| `crates/nono-cli/Cargo.toml` | 5 direct deps: tough, sigstore-trust-root, async-trait, bytes, futures; tokio `macros` feature added | VERIFIED | Lines 71-110 contain all 5 promoted deps with Phase 50 rationale comments; tokio features at line 74 include `macros` |
| `crates/nono-cli/tests/fixtures/tuf-repo-{happy,bad-sig,malformed}/` | 3 fixture dirs with TUF metadata | VERIFIED | All three dirs exist with 1.root.json (2145 bytes happy + bad-sig; 100 bytes malformed), 1.snapshot.json, 1.targets.json, timestamp.json, targets/ subdir; bad-sig differs from happy in signature bytes |
| `crates/nono-cli/tests/fixtures/tuf/trusted_root_baseline.json` | Captured upstream baseline for byte-identity test (R-50-03) | VERIFIED | 6897 bytes JSON file exists; used via `include_bytes!` in Test 4 |
| `scripts/regenerate-tuf-test-fixtures.sh` | Committed regen script (R-50-08) | VERIFIED | 8396 bytes, executable (-rwxr-xr-x); documents tuftool + baseline-gen + bad-sig/malformed transformations |
| `.planning/phases/50-.../50-HUMAN-UAT.md` | Single corp-network scenario + R-50-06/R-50-10 residual risks | VERIFIED | 163 lines; frontmatter `scenarios: 1`; Scenario 1 heading; ### Residual risks section enumerates 4 categories; recording-template includes "If failed, which Residual Risk category applied?" triage field |
| `docs/cli/development/windows-poc-handoff.mdx` | v0.53.x+ note + Caveats subsection; Path B reframed; Phase 49 docs preserved | VERIFIED | grep shows: v0.53 (5 occurrences), from-file (7 — Phase 49 docs preserved), TLS-inspecting/root certificate store (3), air-gapped/outbound network/offline POC (2), Caveats/PAC/proxy auth (4), Known issue Sigstore Rotation subsection preserved (1) |
| `Cross.toml` | Added pre-build hook for x86_64-unknown-linux-gnu (libdbus-1-dev + pkg-config) | VERIFIED | Modified per 50-05-SUMMARY.md; enables `cross clippy` HARD pass on Linux lane |

### Key Link Verification

| From | To | Via | Status | Details |
| ---- | -- | --- | ------ | ------- |
| `setup.rs::refresh_trust_root_step` | `trust_refresh.rs::refresh_production_trusted_root` | `rt.block_on(crate::trust_refresh::refresh_production_trusted_root())` | WIRED | Verified at setup.rs:854; exactly one tree-wide call site |
| `trust_refresh.rs::refresh_production_trusted_root` | `refresh_trusted_root_with_transport(...)` | Direct delegation with PRODUCTION_TUF_ROOT + production URLs + nono_home_dir-rooted datastore | WIRED | Lines 322-329 |
| `refresh_trusted_root_with_transport` | `do_refresh_after_datastore_create_with_root` + cleanup | Inner-helper Result match + single `remove_dir_all(&datastore_for_cleanup)` | WIRED | Lines 244-261 — R-50-05 broadened cleanup, single occurrence in src/ |
| `UreqTransport::fetch` | `tokio::task::spawn_blocking + ureq::Agent::get` | sync-into-async bridge inside `#[async_trait]` fetch impl | WIRED | Line 80 |
| `build_corp_friendly_agent` | `rustls-platform-verifier` (via ureq platform-verifier feature) | `RootCerts::PlatformVerifier` discriminator on TlsConfig | WIRED | Line 147 |
| `mod trust_refresh;` declaration | trust_refresh.rs file | main.rs:94 | WIRED | Module loads; cargo build clean |
| Test 4 `cache_bytes_match_baseline` | `tests/fixtures/tuf/trusted_root_baseline.json` | `include_bytes!("../tests/fixtures/tuf/trusted_root_baseline.json")` | WIRED | Line 593 |
| Test 6 (env-seam) | Public wrapper `refresh_production_trusted_root` via `NONO_TEST_TUF_FIXTURE` | `#[cfg(test)] if let Ok(...)` at trust_refresh.rs:294-297 → `tests::refresh_via_fixture_env_seam` | WIRED | Tested PASS; release build (`cargo build --release`) exits 0, confirming env-seam stripped |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
| -------- | ------------- | ------ | ------------------ | ------ |
| `refresh_production_trusted_root` return value | `TrustedRoot` | Inner helper parses `TrustedRoot::from_json(json)` from bytes fetched via tough's chain walk through the `UreqTransport(ureq::Agent)` | Yes — real bytes from `https://tuf-repo-cdn.sigstore.dev` in production; from in-memory `StaticMapTransport` fixture bytes in tests | FLOWING |
| `serde_json::to_string_pretty(&trusted_root)` in setup.rs | Cache file bytes | TrustedRoot deserializes to JSON via serde — same as Phase 49 reader path | Yes — Test 5 (`cache_file_loadable_by_load_production_trusted_root`) round-trips via `TrustedRoot::from_file` and asserts byte-equality | FLOWING |
| `UreqTransport::fetch` Bytes stream | Vec<u8> from ureq Body | `agent.get(&url_str).call()?.body_mut().read_to_vec()` inside `spawn_blocking` | Yes — real HTTP response bytes flow through to tough | FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| -------- | ------- | ------ | ------ |
| Hermetic test suite passes | `cargo test -p nono-cli --bin nono trust_refresh::tests` | `test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 1057 filtered out; finished in 0.07s` | PASS |
| Release build strips env-seam (no #[cfg(test)] code in release) | `cargo build -p nono-cli --release` | exit 0 (2m 42s, all 5 crates compiled clean) | PASS |
| Module symbol path resolves from setup.rs call site | `cargo build -p nono-cli` (host triple x86_64-pc-windows-msvc) | implicit PASS via test build | PASS |
| Live TLS handshake against tuf-repo-cdn.sigstore.dev consults Windows root store | `nono setup --refresh-trust-root` on TLS-inspecting corp-network Windows host | NOT TESTED — requires real corp-network UAT host (SPEC Req 6 binary acceptance, D-50-09) | SKIP (human verification) |

### Requirements Coverage

REQUIREMENTS.md does NOT define SPEC-50-REQ-1..6 entries. Per the phase plans + ROADMAP.md, the requirements are locked in `50-SPEC.md` (the source of truth for this phase), and ROADMAP.md explicitly references `SPEC-50-REQ-1..6 (locked in 50-SPEC.md)` rather than REQUIREMENTS.md. The SPEC IS the requirements contract for Phase 50.

| Requirement | Source Plan | Description | Status | Evidence |
| ----------- | ----------- | ----------- | ------ | -------- |
| SPEC-50-REQ-1 | 50-01, 50-02, 50-03 | Nono-local TUF chain-walk replaces upstream `TrustedRoot::production()` call | SATISFIED | setup.rs-scoped grep for `TrustedRoot::production()` = 0; new function invoked exactly once in setup.rs:854 |
| SPEC-50-REQ-2 | 50-02 | HTTP client consults Windows certificate store via ureq + platform-verifier | SATISFIED | trust_refresh.rs:147 `RootCerts::PlatformVerifier`; zero `reqwest::Client::builder` in trust_refresh.rs |
| SPEC-50-REQ-3 | 50-02, 50-04 | TUF verification correctness preserved (no hand-rolled signature math) | SATISFIED | Zero `verify_role`/`Signed<Root>` hand-rolling in src/; Test 2 (`bad_signature_at_root_surfaces_as_nono_error_setup`) PASSES — tough rejects bad sig |
| SPEC-50-REQ-4 | 50-02, 50-03, 50-04 | Cache file byte-identical to upstream output | SATISFIED | Test 4 (`cache_bytes_match_baseline`) PASSES via `include_bytes!` against captured upstream baseline (6897 bytes); Test 5 (`cache_file_loadable_by_load_production_trusted_root`) PASSES — Phase 32 D-32-01 reader unaffected |
| SPEC-50-REQ-5 | 50-04 | ≥4 hermetic tests; pass cross-OS | SATISFIED (host) | 6 tests PASS on Windows host (verified during this pass); cross-OS for hermetic tests asserted by lack of platform-specific code in test module — Linux lane verified via cross clippy at HEAD `60214a28` |
| SPEC-50-REQ-6 | 50-05 | HUMAN-UAT scenario for corp-network proof | SATISFIED (artifact); PENDING (live run) | 50-HUMAN-UAT.md exists with required scenario + R-50-06/R-50-10 residual-risk sections; binary acceptance pass criterion awaits POC-user execution per D-50-09 |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| ---- | ---- | ------- | -------- | ------ |
| (none in Phase 50 production code) | — | — | — | — |

Search results for stub indicators in trust_refresh.rs / setup.rs (Phase 50 production code):
- No `TODO|FIXME|XXX|HACK|PLACEHOLDER` markers
- No `return null|return {}|return []|=> {}` empty implementations
- No `console.log`-only handlers (N/A for Rust)
- No `.unwrap()`/`.expect()` in production code (`#[cfg(test)]` module legitimately uses `.expect()` and `.unwrap()` under `#[allow]` attributes — standard pattern)
- 403/404/410 → FileNotFound normalization is a documented intentional choice tied to tough's chain-walk contract (R-50-10 residual risk acknowledged in inline comment + HUMAN-UAT)

50-REVIEW.md (independent code review at HEAD `60214a28`) recorded:
- 0 critical findings
- 5 warning findings (post-phase polish opportunities; none block goal achievement):
  - WR-01: Path A skips freshness gate that Path B enforces (cosmetic asymmetry)
  - WR-02: cleanup wipes datastore on transient failures (defeats tough's incremental optimization)
  - WR-03: sync `std::fs::remove_dir_all` inside async fn (executor blocking, bounded)
  - WR-04: phase-index helper shared with --from-file (mutex prevents misuse today)
  - WR-05: JoinError mapped to generic TransportErrorKind::Other (diagnostic loss)
- 4 info findings (maintainability)

These are out-of-scope for Phase 50 goal verification — they document follow-up polish, not stubs blocking the phase outcome.

### Human Verification Required

#### 1. Corp-network UAT — `nono setup --refresh-trust-root` succeeds on TLS-inspecting Windows host

**Test:**
1. Install Phase 50 close-SHA nono build (v0.53.x+) on a Windows 10/11 host behind a TLS-inspecting corporate proxy whose enterprise CA is present in `HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT`.
2. Delete any pre-existing `$env:USERPROFILE\.nono\trust-root\trusted_root.json`.
3. Run `nono setup --refresh-trust-root` from a PowerShell prompt.
4. Append the recording-template entry from 50-HUMAN-UAT.md to this VERIFICATION.md.

**Expected:**
- Step `[3/5] Refreshing Sigstore trusted root...` exits 0.
- `$env:USERPROFILE\.nono\trust-root\trusted_root.json` exists and is non-empty.
- Stderr contains ZERO `error sending request for url` errors.

**Why human:**
- SPEC Req 6 (line 50-53) makes this UAT the dispositive proof that ureq + rustls-platform-verifier actually consults the Crypt32 root store as advertised. Per D-50-09: "this UAT is the ONLY real TLS-stack check for Phase 50 — hermetic unit tests deliberately do not exercise a real TLS handshake."
- A real corp-network host with the right CA-deployment profile cannot be simulated in CI without significant infrastructure investment (out of scope per round-2 user lock).
- 4 Residual Risk categories (R-50-06 + R-50-10) define triage for any FAIL outcome so the result is unambiguous.

### Gaps Summary

No actionable gaps. All 6 SPEC-50-REQ-* truths are satisfied at the artifact + wiring + data-flow + behavioral-test layers verifiable without a real corp-network host. The phase goal artifacts are complete, wired end-to-end, and pass hermetic + cross-target verification (Linux lane HARD; macOS lane PARTIAL with explicit user sign-off per the cross-target-verify-checklist.md disposition).

The sole open gate is SPEC Req 6's binary pass criterion (live UAT run on a real corp-network Windows host), which the phase plan + ROADMAP explicitly mark as the orchestrator/POC-user gate (Row 9 of the 50-05-SUMMARY.md SPEC acceptance table, marked PENDING). This is by design: D-50-09 makes the HUMAN-UAT the only real TLS-stack check.

Phase status should advance to `human_needed` (not `passed`) until the UAT row is closed. After UAT pass, this VERIFICATION.md should be appended with the recording-template entry; status flips to `passed`.

---

_Verified: 2026-05-22T00:00:00Z_
_Verifier: Claude (gsd-verifier)_
