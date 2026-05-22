---
phase: 50
plan: 02
subsystem: nono-cli/trust-refresh
tags:
  - sigstore
  - tuf
  - trust-root
  - corp-network
  - chain-walk
  - ureq
  - platform-verifier
  - wave-1
requires:
  - tough 0.22.0 (direct dep from Plan 50-01)
  - sigstore-trust-root 0.7.0 (direct dep from Plan 50-01)
  - async-trait 0.1.89 (direct dep from Plan 50-01)
  - bytes 1.11.1 (direct dep from Plan 50-01)
  - futures 0.3.32 (direct dep from Plan 50-01)
  - ureq 3.3.0 with `platform-verifier` feature (already declared at nono-cli/Cargo.toml:109)
provides:
  - "crate::trust_refresh::refresh_production_trusted_root (full impl: TUF chain-walk + OS-root-store HTTP transport)"
  - "UreqTransport (private module-scope tough::Transport adapter for ureq::Agent)"
  - "build_corp_friendly_agent (private agent factory with RootCerts::PlatformVerifier)"
  - "do_refresh_after_datastore_create (private inner helper for R-50-05 broadened cleanup semantics)"
affects:
  - crates/nono-cli/src/trust_refresh.rs
tech-stack:
  added:
    - "(none — all 5 direct-dep promotions landed in Plan 50-01)"
  patterns:
    - "sync->async bridge via tokio::task::spawn_blocking inside #[async_trait] impl"
    - "single inner-helper Result match for broadened cleanup semantics (R-50-05)"
    - "verbatim port of sigstore-trust-root-0.7.0/src/tuf.rs::TufClient::load_repository with two substitutions (transport + datastore path)"
key-files:
  modified:
    - crates/nono-cli/src/trust_refresh.rs
decisions:
  - "Import `nono::trust::TrustedRoot` (re-export at crates/nono/src/trust/bundle.rs:32) rather than `sigstore_verify::trust_root::TrustedRoot`, because `sigstore-verify` is not a direct dep of `nono-cli` — same Wave 0 fix Plan 01 applied. Functionally identical."
  - "Use `Body::read_to_vec(&mut self)` (Option A) for the ureq body read inside the spawn_blocking closure — `read_to_vec` exists at ureq-3.3.0/src/body/mod.rs:329, so the universal `into_reader()` fallback is not needed and no `use std::io::Read;` import is required."
  - "Keep `#[allow(dead_code)]` on `refresh_production_trusted_root` — Plan 50-03 (the call-site swap in setup.rs) is what removes it. Removing it now would re-trigger the bin-crate dead_code lint and fail strict clippy until Plan 03 lands."
  - "Pass `url.as_str()` (which is `&str` and impl `AsRef<str>`) to `TransportError::new`/`new_with_cause` rather than the `Url` value, since `TransportError`'s constructors require `AsRef<str>`. `Url` does impl `AsRef<str>` (url-2.5.8/src/lib.rs:2867) but using `.as_str()` is more explicit and avoids any move semantics on the `Url` value where we need it twice across match arms."
metrics:
  tasks_completed: 2
  files_changed: 1
  commits: 1
  completed_date: 2026-05-21
---

# Phase 50 Plan 02: UreqTransport + TUF chain-walk implementation — Summary

**One-liner:** Replaced the Wave 0 stub `refresh_production_trusted_root()` with a verbatim port of `sigstore-trust-root-0.7.0/src/tuf.rs::TufClient::load_repository`, substituting nono's `UreqTransport(ureq::Agent)` (platform-verifier-backed) for tough's `HttpTransport` and nono's `nono_home_dir()`-rooted datastore for sigstore-rs's `directories`-based cache path, with a single broadened cleanup path (R-50-05) covering every post-`create_dir_all` failure.

## Tasks Completed

| # | Task | Commit | Files |
|---|------|--------|-------|
| 1 | Verify ureq 3.3.0 Body-reading API; resolve Open Question A1 | (no separate commit — finding recorded inline in this SUMMARY and in the production code's commit body) | (read-only — confirmed `Body::read_to_vec(&mut self) -> Result<Vec<u8>, Error>` at ureq-3.3.0/src/body/mod.rs:329) |
| 2 | Implement UreqTransport + refresh_production_trusted_root with broadened cleanup | `dec8f44f` | `crates/nono-cli/src/trust_refresh.rs` (+218 / −16) |

## Task 1 Finding (ureq Body API)

The plan's Task 1 was a read-only investigation. Two body-reading APIs were located in ureq 3.3.0:

| API | Location | Self semantics | Return |
|-----|----------|----------------|--------|
| `Body::read_to_vec` | `ureq-3.3.0/src/body/mod.rs:329` | `&mut self` | `Result<Vec<u8>, ureq::Error>` |
| `Body::into_reader` | `ureq-3.3.0/src/body/mod.rs:264` | `self` (consumes) | `BodyReader<'static>` (requires `std::io::Read`) |

**Chosen for Task 2:** `Body::read_to_vec` (Option A per the plan). The closure inside `tokio::task::spawn_blocking` is two lines:

```rust
let mut resp = agent.get(&url_str).call()?;
resp.body_mut().read_to_vec()
```

No `use std::io::Read;` import is required. RESEARCH.md Open Question 1 closed, A1 confirmed.

## Task 2 Implementation Map

| Section of trust_refresh.rs | Lines | Source (verbatim port reference) |
|-----------------------------|-------|-----------------------------------|
| `UreqTransport` struct + `impl Transport` | ~68-134 | RESEARCH.md Pattern 1 (lines 211-265) |
| `build_corp_friendly_agent()` | ~144-157 | RESEARCH.md Pattern 2 (lines 274-302), Example A (lines 567-583) |
| `do_refresh_after_datastore_create()` (inner helper) | ~165-196 | New helper — R-50-05 broadened-cleanup factoring |
| `refresh_production_trusted_root()` | ~218-275 | RESEARCH.md Pattern 3 (lines 309-376), with R-50-05 outer-match cleanup |

### Codex review-finding implementation

| Review-finding | Implementation |
|----------------|----------------|
| R-50-05 (broadened cleanup) | Inner `do_refresh_after_datastore_create` helper holds ALL fallible work after `create_dir_all` succeeds; outer function captures one `Result` and runs `remove_dir_all(&datastore_for_cleanup)` once on `Err`. Grep confirms exactly 1 occurrence of the cleanup line. |
| R-50-10 (403 misdirection) | The 403/404/410-as-FileNotFound mapping is required by tough's chain-walk termination contract (`tough-0.22.0/src/http.rs:126-130`). The misdirection risk (corp-proxy 403 looks like missing root) is documented as a residual-risk note in the inline `// NOTE (Codex R-50-10):` comment block at the match arm and will be repeated in Plan 50-05's HUMAN-UAT residual-risk section. |
| R-50-02 (module-doc hygiene) | The literal `TrustedRoot::production()` symbol string does not appear anywhere in the file (`grep -cE 'TrustedRoot::production\(\)' crates/nono-cli/src/trust_refresh.rs` returns 0). Module docs use the phrasing "upstream production helper" / "upstream call". |
| R-50-01 (direct-dep imports resolvable) | All five Plan 50-01 dep promotions (`tough`, `sigstore-trust-root`, `async-trait`, `bytes`, `futures`) resolve directly at first compile. Zero new Cargo.toml edits were required. |

## Verification

| Check | Expected | Actual | Pass |
|-------|----------|--------|------|
| `cargo build -p nono-cli` (host triple x86_64-pc-windows-msvc) | exit 0 | exit 0 (2m 49s) | ✓ |
| `cargo clippy -p nono-cli --no-deps -- -D warnings -D clippy::unwrap_used` (host triple) | exit 0 | exit 0 (1m 28s; re-run 0.61s cached) | ✓ |
| `grep -cE '^impl Transport for UreqTransport' crates/nono-cli/src/trust_refresh.rs` | 1 | 1 | ✓ |
| `grep -cE 'tokio::task::spawn_blocking' crates/nono-cli/src/trust_refresh.rs` | ≥ 1 | 2 (1 code + 1 doc-comment) | ✓ |
| `grep -cE 'RootCerts::PlatformVerifier' crates/nono-cli/src/trust_refresh.rs` | 1 (plan: "exactly 1") | 2 (1 code at line 147 + 1 doc-comment at line 137) | ✓ (see Deviations §1) |
| `grep -cE 'RepositoryLoader::new\(&PRODUCTION_TUF_ROOT' crates/nono-cli/src/trust_refresh.rs` | 1 | 1 | ✓ |
| `grep -cE '\.datastore\(datastore_dir\)' crates/nono-cli/src/trust_refresh.rs` | 1 | 1 | ✓ |
| `grep -cE 'TrustedRoot::from_json' crates/nono-cli/src/trust_refresh.rs` | 1 (plan: "exactly 1") | 3 (1 code at line 194 + 2 doc-comments at lines 41, 259) | ✓ (see Deviations §1) |
| `grep -cE 'reqwest::Client' crates/nono-cli/src/trust_refresh.rs` | 0 | 0 | ✓ |
| `grep -cE 'verify_role\|Signed<Root>\|hand.*roll' crates/nono-cli/src/trust_refresh.rs` | 0 | 0 | ✓ |
| `.unwrap()` / `.expect(` in non-comment lines | 0 | 0 | ✓ |
| `pub async fn refresh_production_trusted_root() -> Result<TrustedRoot>` signature | 1 | 1 | ✓ |
| `async fn do_refresh_after_datastore_create` | 1 | 1 | ✓ |
| `remove_dir_all(&datastore_for_cleanup)` (R-50-05 single cleanup path) | 1 | 1 | ✓ |
| `code == 403 \|\| code == 404 \|\| code == 410` (Pitfall 4) | 1 | 1 | ✓ |
| `TrustedRoot::production()` literal (R-50-02 hygiene) | 0 | 0 | ✓ |

### Cross-target clippy (D-50-13 HARD pass)

**NOT attempted in Plan 02.** Plan 01's pre-flight (Task 0) surfaced BLOCKER-50-01: the dev host lacks `x86_64-linux-gnu-gcc` and `cc` (macOS SDK) cross-toolchains needed by `cc-rs` for C-source dependencies (aws-lc-rs/ring). Plan 02's verification scope is host-triple only; the cross-target requirement is owned by Plan 50-05 verification. The blocker carries forward unchanged from Plan 01's SUMMARY.

## Deviations from Plan

### §1 — Rule 1 (interpretation correction) — positive grep counts include doc-comment references

- **Found during:** Task 2 acceptance grep run
- **Issue:** Plan acceptance criteria say `grep -nE 'RootCerts::PlatformVerifier' ... returns exactly 1 match` and `grep -nE 'TrustedRoot::from_json' ... returns exactly 1 match`. Actual counts are 2 and 3 respectively because doc-comments reference these symbols by name (RootCerts::PlatformVerifier appears once in code at line 147 and once in the doc-comment for `build_corp_friendly_agent` at line 137; TrustedRoot::from_json appears once in code at line 194 and twice in doc-comments at lines 41 and 259).
- **Interpretation:** The acceptance criterion is meant to verify the code includes the symbol — the strict "exactly 1" reading would force removing the doc-comment references, which would degrade documentation quality with no security/correctness benefit. The substantive criteria (the symbol is present in code; no `reqwest::Client`; no hand-rolled crypto; no `.unwrap()`; no `TrustedRoot::production()` literal) all pass exactly as the plan intended.
- **Fix:** Preserve the doc-comment references as the code-quality-correct choice. This SUMMARY documents the count discrepancy explicitly so reviewers see it.
- **Files modified:** None (interpretation, not behavior)
- **Commit:** N/A (recorded here)

### §2 — Procedural mishap — Task 1 scratch commit landed on `main`, not `worktree-agent-aa8a5f5b1a95548f9`

- **Found during:** Right after the Task 1 commit attempt
- **Issue:** This executor's bash shell defaulted to CWD `C:\Users\OMack\Nono` (the main checkout) rather than the assigned worktree `C:\Users\OMack\Nono\.claude\worktrees\agent-aa8a5f5b1a95548f9\`. The agent-startup `<worktree_branch_check>` script correctly verified the worktree's HEAD was `worktree-agent-aa8a5f5b1a95548f9`, but because all subsequent bash commands inherit the main-checkout CWD (a Windows worktree environment quirk; persistent across commands per the tool's documented shell semantics), the Task 1 scratch-note commit `bfc1455a docs(50-02): record Task 1 ureq Body API finding` landed on `main` instead of the worktree branch.
- **Impact assessment:** The commit added ONLY a transient `// Phase 50 Plan 02 Task 1 finding: ureq 3.3.0 Body API` scratch comment to the top of `crates/nono-cli/src/trust_refresh.rs`. The plan explicitly states Task 1's note is "a contemporary working note" that Task 2 would overwrite — there is no semantic loss from undoing it. Task 2 was redone correctly in the worktree (commit `dec8f44f` on `worktree-agent-aa8a5f5b1a95548f9`).
- **Recovery action attempted:** None — per CLAUDE.md / GSD `<destructive_git_prohibition>` rules, the executor MUST NOT run `git reset --hard` on `main` (or any other destructive op on a protected ref) without explicit user authorization, even when undoing a commit the executor itself just created. The safe self-recovery path is to surface the issue rather than auto-remediate (#2924).
- **Affected commit:** `bfc1455a` on `main` (DCO-signed; one-file scratch comment).
- **Recommended orchestrator remediation:** Either (a) `git reset --hard HEAD~1` on `main` to drop the rogue commit (it's purely additive and re-derivable from the SUMMARY's "Task 1 Finding" section above), or (b) keep it and let the next legitimate `main` commit overwrite the same file with Plan 50-03's content. Option (a) is cleaner. Option (b) leaves `main` with a one-commit pre-image of Plan 50-02 work that the next merge will harmlessly supersede.
- **Files affected:** `crates/nono-cli/src/trust_refresh.rs` on `main` only — no impact on the worktree branch where this Plan 50-02 actually landed.
- **Lesson for future executors:** When a worktree path differs from the bash default CWD, prefix EVERY bash command with `cd <worktree-path> &&` to force the correct workspace. Do this even if the env says CWD is the worktree — the persistent-CWD model of bash sessions in this tool may diverge from the env-declared starting dir on Windows worktrees.

### §3 — Skipped Task 1 commit on the worktree branch (no semantic impact)

- **Found during:** Recovery from §2
- **Issue:** Because §2 already committed the Task 1 scratch comment to `main` (and that comment was intended to be transient anyway), making a second Task 1 commit on the worktree would duplicate the work and produce a noisy commit history. The plan does NOT require a separate Task 1 commit — Task 1's `<action>` block is a read-only investigation whose deliverable is "the chosen API name is recorded as a comment in `crates/nono-cli/src/trust_refresh.rs` for Task 2 to consume." Task 2 immediately overwrites that comment.
- **Fix:** The Task 1 finding is recorded in this SUMMARY's "Task 1 Finding (ureq Body API)" section above AND in the Task 2 commit body. The transient comment is absent from the worktree's `trust_refresh.rs` (which goes straight from Wave 0 skeleton to Plan 02 final), which matches the plan's "Do NOT add the comment block as a permanent feature of the production file" guidance.
- **Files modified:** None (skipped commit, not a code change)
- **Commit:** N/A

### §4 — `#[allow(dead_code)]` preserved on `refresh_production_trusted_root`

- **Found during:** Task 2 strict clippy
- **Issue:** The Wave 0 skeleton's `#[allow(dead_code)]` attribute was preserved on `refresh_production_trusted_root` because Plan 50-03 (call-site swap in `setup.rs`) has not landed yet — without it, strict clippy fails with `dead_code` in the bin crate. The plan's Task 2 acceptance does not explicitly call out keeping or removing the attribute.
- **Fix:** Keep the attribute (and its explanatory comment) as-is. Plan 50-03's deliverable removes it once the call site is wired. This is the same pattern Plan 50-01 established and documented as a Rule-3 fix.
- **Files modified:** `crates/nono-cli/src/trust_refresh.rs` (the `#[allow(dead_code)]` remains on the public function)
- **Commit:** `dec8f44f`

## Confirmations Required by Plan Output Block

### Wave 1 production code landed

`crates/nono-cli/src/trust_refresh.rs` now contains the full implementation:
- `struct UreqTransport { agent: Agent }` (module-private)
- `impl Transport for UreqTransport` (async fetch via spawn_blocking)
- `fn build_corp_friendly_agent() -> Agent` (RootCerts::PlatformVerifier)
- `async fn do_refresh_after_datastore_create(...)` (inner helper for R-50-05)
- `pub async fn refresh_production_trusted_root() -> Result<TrustedRoot>` (public surface, signature unchanged from Plan 01 skeleton)

### Task 1 finding: which ureq Body API was chosen

**`Body::read_to_vec(&mut self) -> Result<Vec<u8>, ureq::Error>`** — Option A per the plan. Located at `ureq-3.3.0/src/body/mod.rs:329`. No `std::io::Read` import is required.

### Confirmation that the CONTEXT.md async-claim correction (RESEARCH.md A4) is honored

YES — `refresh_production_trusted_root()` is declared `pub async fn`. Inside `UreqTransport::fetch`, the sync `ureq::Agent::get(...).call()` is bridged into the async trait method via `tokio::task::spawn_blocking`. The caller (`setup.rs::refresh_trust_root_step` — Plan 50-03's target) still needs the `tokio::runtime::Builder::new_current_thread()` block; CONTEXT.md's claim that the runtime can be eliminated remains incorrect.

### Confirmation that ALL imports resolved without late Cargo.toml edits (R-50-01 closure verified end-to-end)

YES — the five Plan 50-01 dep promotions (`tough`, `sigstore-trust-root`, `async-trait`, `bytes`, `futures`) plus the existing `ureq = { version = "3", features = ["platform-verifier"] }` declaration at `crates/nono-cli/Cargo.toml:109` cover every import:

```rust
use async_trait::async_trait;
use bytes::Bytes;
use futures::stream;
use nono::trust::TrustedRoot;
use nono::{NonoError, Result};
use sigstore_trust_root::{DEFAULT_TUF_URL, PRODUCTION_TUF_ROOT, TRUSTED_ROOT_TARGET};
use std::path::PathBuf;
use std::time::Duration;
use tough::{
    IntoVec, RepositoryLoader, TargetName, Transport, TransportError, TransportErrorKind,
    TransportStream,
};
use ureq::tls::{RootCerts, TlsConfig};
use ureq::Agent;
use url::Url;
```

`cargo build -p nono-cli` exited 0 on first attempt. Plan 50-01's R-50-01 closure is verified end-to-end.

### Cleanup-path grep result: exactly 1 occurrence of `remove_dir_all(&datastore_for_cleanup)`

```bash
$ grep -cE 'remove_dir_all\(&datastore_for_cleanup\)' crates/nono-cli/src/trust_refresh.rs
1
```

Confirmed — R-50-05 broadened-cleanup intent satisfied. The single cleanup call lives in the outer `refresh_production_trusted_root` function (line 269) and runs on ANY `Err` from `do_refresh_after_datastore_create`, which covers TUF load / read_target / IntoVec / UTF-8 / TrustedRoot::from_json failures.

### Compile-time adjustments made vs the action-block code

Two small adjustments relative to the plan's action-block code:

1. **`url.as_str()` instead of `url.clone()` / `url` for `TransportError::new*` calls.** The plan's snippet passed `url.clone()` (first arm) and `url` (other arms) directly. `TransportError::new<S: AsRef<str>>` and `new_with_cause<S: AsRef<str>, E>` accept anything `AsRef<str>`, and `url::Url` does impl `AsRef<str>` (url-2.5.8/src/lib.rs:2867). Using `url.as_str()` makes the intent explicit and avoids any cloning since the `&str` borrow is what the API actually consumes. No behavioral difference; the URL stored in `TransportError` is byte-identical.

2. **Removed `use tough::IntoVec;` from inside `do_refresh_after_datastore_create`.** The plan's snippet had `use tough::IntoVec;` inside the function body as a workaround for the case where `IntoVec` was not in the top-level prelude. `tough::IntoVec` IS in tough 0.22.0's top-level prelude (`tough-0.22.0/src/lib.rs:59 → pub use crate::transport::IntoVec;`), so the use can live with the other tough imports at module scope. Function semantics unchanged.

Neither adjustment changes the production behavior or any acceptance criterion; both are stylistic improvements that came out of the cross-reference against actual on-disk crate source (see "Read APIs verified" below).

### Read APIs verified (additional rigor)

To pre-empt the "API drift" risks called out in RESEARCH.md §Pitfalls 3 and 4 and §Open Questions, the executor cross-referenced the following against on-disk crate source before/during Task 2:

| API | Path | Confirmation |
|-----|------|--------------|
| `ureq::Body::read_to_vec` | `ureq-3.3.0/src/body/mod.rs:329` | `pub fn read_to_vec(&mut self) -> Result<Vec<u8>, Error>` — exists |
| `ureq::Error::StatusCode(u16)` | `ureq-3.3.0/src/error.rs:14` | enum variant exists; `From<io::Error>` impl at line 216 |
| `ureq::tls::RootCerts::PlatformVerifier` | `ureq-3.3.0/src/tls/mod.rs:294,303` | enum variant exists |
| `tough::Transport` trait | `tough-0.22.0/src/transport.rs:46-49` | `#[async_trait]`; `fetch` returns `Result<TransportStream, TransportError>` |
| `tough::IntoVec` (top-level) | `tough-0.22.0/src/lib.rs:59` | re-exported via `pub use crate::transport::IntoVec;` — works in top-level `use tough::IntoVec` |
| `tough::TransportError::new<S: AsRef<str>>` | `tough-0.22.0/src/transport.rs:110` | requires `AsRef<str>` |
| `tough::TransportError::new_with_cause<S: AsRef<str>, E: Into<Box<dyn Error + Send + Sync>>>` | `tough-0.22.0/src/transport.rs:122` | requires `AsRef<str>` + `Into<Box<dyn Error...>>` |
| `tough::RepositoryLoader::new(root: &'a impl AsRef<[u8]>, ...)` | `tough-0.22.0/src/lib.rs:193` | takes `&'a impl AsRef<[u8]>` — `&PRODUCTION_TUF_ROOT` works |
| `tough::Repository::read_target` | `tough-0.22.0/src/lib.rs:458-499` | `async fn`; returns `Result<Option<impl Stream + IntoVec<...>>>` |
| `tough::TargetName::new<S: Into<String>>` | `tough-0.22.0/src/target_name.rs:33` | takes `Into<String>` |
| `sigstore_trust_root` consts | `sigstore-trust-root-0.7.0/src/tuf.rs:48,60,69` (re-exported in lib.rs:100-104 when `tuf` feature is on) | feature enabled in this build (confirmed via `cargo tree -p nono-cli -e features`) |
| `sigstore_trust_root::TrustedRoot::from_json(json: &str) -> Result<Self>` | `sigstore-trust-root-0.7.0/src/trusted_root.rs:176` | exists; same parser the cache reader at `crates/nono/src/trust/bundle.rs` uses |
| `nono::trust::TrustedRoot` (re-export of `sigstore_verify::trust_root::TrustedRoot` which is itself `pub use sigstore_trust_root as trust_root;`) | `crates/nono/src/trust/bundle.rs:32` → `sigstore-verify-0.7.0/src/lib.rs:38` | the re-export chain works; nono-cli does NOT need a direct `sigstore-verify` dep |
| `url::Url` impl `AsRef<str>` | `url-2.5.8/src/lib.rs:2867` | exists; safe to pass `url.as_str()` to `TransportError::new` |

All API surfaces matched RESEARCH.md's expectations; no late Cargo.toml edits or workarounds were needed.

## Threat Surface Scan

No new attack surface was introduced beyond what the plan's `<threat_model>` already enumerates. The Wave 1 implementation matches the threat-register dispositions (all `mitigate` items implemented; T-50-02-04 `accept` documented in module docs). Specifically:

- T-50-02-01 (TUF chain bypass / hand-rolled crypto): MITIGATED — grep guard returns 0; all signature math routes through `tough::RepositoryLoader::load`.
- T-50-02-02 (Transport-level MitM downgrade): MITIGATED — `RootCerts::PlatformVerifier` discriminator present at line 147; rustls-platform-verifier rejects untrusted chains, surfacing as `TransportErrorKind::Other` (fail-secure).
- T-50-02-03 (Cache poisoning / partial write): MITIGATED — single `remove_dir_all(&datastore_for_cleanup)` cleanup path; grep returns exactly 1.
- T-50-02-04 (TOCTOU on datastore symlinks): ACCEPTED — risk is bounded (user's own home dir); documented in module docs implicitly via the `tough`-managed datastore reference.
- T-50-02-05 (async deadlock): MITIGATED — every `agent.get(...).call()` is wrapped in `tokio::task::spawn_blocking`; `JoinError` is mapped to `TransportErrorKind::Other`, never panicked.
- T-50-02-06 (Status-code mis-classification, incl. R-50-10 corp-proxy 403 misdirection): MITIGATED for chain-walk correctness; ACCEPTED for the residual debugging-misdirection risk (documented inline at the match arm + carried forward to Plan 05's HUMAN-UAT residual-risk).
- T-50-02-07 (Endless-data attack): ACCEPTED — `tough::Limits.max_root_size = 1 MiB` default still applies; nono adds no new size limit.
- T-50-02-08 (Network timeout exhaustion): MITIGATED — 30s global / 10s connect on the agent.
- T-50-02-09 (Cleanup-path semantic gap from R-50-05): MITIGATED — single-Result outer match covers every post-`create_dir_all` failure.

No new `threat_flag` entries are required.

## Known Stubs

None for this plan. The function body has zero hardcoded empty/placeholder values; every code path either succeeds with a real `TrustedRoot` value parsed from `tough`'s output bytes or returns `NonoError::Setup(...)`. The `#[allow(dead_code)]` attribute is not a stub in the runtime-data sense — it's an artifact of the inter-plan ordering where Plan 03 wires the call site (documented above in Deviations §4).

## Self-Check: PASSED

- File `crates/nono-cli/src/trust_refresh.rs` exists in the worktree at HEAD `dec8f44f`: FOUND
- Commit `dec8f44f feat(50-02): implement UreqTransport + TUF chain-walk in trust_refresh` exists on `worktree-agent-aa8a5f5b1a95548f9`: FOUND (`git log --oneline -3` lists it as HEAD)
- `cargo build -p nono-cli` exit 0 (host triple): VERIFIED
- `cargo clippy -p nono-cli --no-deps -- -D warnings -D clippy::unwrap_used` exit 0 (host triple): VERIFIED
- All 14 acceptance grep checks: PASSED (positive checks 3 + 6 over-count via doc-comments — documented in Deviations §1; all critical negative checks return 0)
- Cleanup-path single-call grep: 1 occurrence (R-50-05 broadened semantics)
- TrustedRoot::production() literal hygiene (R-50-02): 0 occurrences
- Async signature (RESEARCH.md A4): `pub async fn refresh_production_trusted_root() -> Result<TrustedRoot>` preserved verbatim from Plan 50-01 skeleton

## Orchestrator Notes

1. **Rogue commit on `main` (`bfc1455a`):** See Deviations §2 — recommended remediation `git reset --hard HEAD~1` on `main` to drop the additive scratch-comment commit. Safe because no concurrent commits are present beyond it.

2. **Wave 1 dependency for Plan 50-03:** The stable symbol `crate::trust_refresh::refresh_production_trusted_root() -> nono::Result<nono::trust::TrustedRoot>` is now the real implementation, not a stub. Plan 50-03 can swap `setup.rs::refresh_trust_root_step`'s `rt.block_on(...)` argument from `nono::trust::TrustedRoot::production()` to `crate::trust_refresh::refresh_production_trusted_root()` and remove the `#[allow(dead_code)]` attribute in the same commit.

3. **Cross-target verification deferred:** BLOCKER-50-01 from Plan 50-01 carries forward unchanged. Plan 05's verification owns the resolution.
