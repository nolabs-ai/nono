---
phase: 50
plan: 01
subsystem: nono-cli/trust-refresh
tags:
  - sigstore
  - tuf
  - trust-root
  - corp-network
  - skeleton
  - wave-0
requires:
  - sigstore-trust-root 0.7.0 (transitive, promoted to direct)
  - tough 0.22.0 (transitive, promoted to direct)
  - async-trait 0.1.89 (transitive, promoted to direct)
  - bytes 1.11.1 (transitive, promoted to direct)
  - futures 0.3.32 (transitive, promoted to direct)
provides:
  - crate::trust_refresh::refresh_production_trusted_root (async stub)
  - 5 direct-dep edges in nono-cli for Plan 02 import surface
affects:
  - crates/nono-cli/Cargo.toml
  - crates/nono-cli/src/main.rs (mod decl)
  - crates/nono-cli/src/trust_refresh.rs (new module)
tech-stack:
  added:
    - tough 0.22.0 (direct dep — TUF chain-walk verification)
    - sigstore-trust-root 0.7.0 (direct dep — consts for Plan 02)
    - async-trait 0.1.89 (direct dep — Transport trait impl macro)
    - bytes 1.11.1 (direct dep — Bytes stream item type)
    - futures 0.3.32 (direct dep — stream::iter helper)
  patterns:
    - "interface-first ordering: skeleton symbol unblocks parallel Wave 1 work"
    - "transitive → direct dep promotion (no Cargo.lock package/version churn)"
key-files:
  created:
    - crates/nono-cli/src/trust_refresh.rs
  modified:
    - crates/nono-cli/Cargo.toml
    - crates/nono-cli/src/main.rs
decisions:
  - "Use `nono::trust::TrustedRoot` (re-export at crates/nono/src/trust/bundle.rs:32) instead of `sigstore_verify::trust_root::TrustedRoot` because `sigstore-verify` is not a direct dep of nono-cli — Rule 3 fix; functionally identical."
  - "Apply `#[allow(dead_code)]` to the skeleton function with explanatory comment — Rule 3 fix needed because nothing in the bin crate calls the symbol until Plan 03; pattern well-precedented (17 existing nono-cli files use it)."
  - "Commit Tasks 2+3 together because Task 2's `mod trust_refresh;` declaration does not compile without Task 3's module file — the plan's Task 2 acceptance note explicitly anticipates this coupling."
metrics:
  duration_seconds: 633
  tasks_completed: 4
  files_changed: 3
  commits: 2
  completed_date: 2026-05-22
---

# Phase 50 Plan 01: Wave 0 skeleton + cross-target pre-flight — Summary

**One-liner:** Promoted `tough` + 4 sibling transitive crates to direct deps of `nono-cli` and seeded an async skeleton `refresh_production_trusted_root()` that unblocks parallel Wave 1 work (Plans 02 + 03) while preserving the P32-CHK-002 / D-32-15 HTTP-free invariant on the core library.

## Tasks Completed

| # | Task | Commit | Files |
|---|------|--------|-------|
| 0 | Cross-target rustup toolchain pre-flight | (no files) | rustup state inspected; cross-target gap surfaced (see Blockers) |
| 1 | Promote `tough` + 4 transitive crates to direct deps | `9c8b9244` | `crates/nono-cli/Cargo.toml`, `Cargo.lock` |
| 2 | Add `mod trust_refresh;` declaration | `bebb3dc6` | `crates/nono-cli/src/main.rs` |
| 3 | Create skeleton `crates/nono-cli/src/trust_refresh.rs` | `bebb3dc6` | `crates/nono-cli/src/trust_refresh.rs` |

## Task 0 Pre-flight Audit Trail

### Rustup target inventory

`rustup target list --installed` (before and after — both rustup add commands were idempotent no-ops):

```
x86_64-apple-darwin
x86_64-pc-windows-msvc
x86_64-unknown-linux-gnu
```

### Rustup add exit codes

```
rustup target add x86_64-unknown-linux-gnu  →  exit 0  (component rust-std up to date)
rustup target add x86_64-apple-darwin       →  exit 0  (component rust-std up to date)
```

### Smoke `cargo check` exit codes (the actual D-50-13 readiness probe)

```
cargo check --workspace --target x86_64-unknown-linux-gnu  →  exit 101  (FAIL)
cargo check --workspace --target x86_64-apple-darwin       →  exit 101  (FAIL)
```

**Linux failure root cause:**

```
error occurred in cc-rs: failed to find tool "x86_64-linux-gnu-gcc":
program not found (see https://docs.rs/cc/latest/cc/#compile-time-requirements for help)
```

**macOS failure root cause:**

```
error occurred in cc-rs: failed to find tool "cc":
program not found
```

Both failures come from C-source dependencies (likely `aws-lc-rs` or `ring`) needing a system C cross-compiler that is not present on this Windows dev host. The rustup rust-std targets ARE installed and functional in the Rust sense, but `cc-rs` cannot find a backing C toolchain to compile native code for the foreign triples.

### Phase 50 blocker (per Task 0 acceptance)

The plan's Task 0 action block explicitly anticipated this outcome (lines 162-167):

> A `cargo check` failure here would indicate a missing system library (e.g., on a Windows dev host trying to cross-compile to Linux without the GNU toolchain). In that rare case:
> - Document the missing system component in 50-01-SUMMARY.md
> - Flag the gap as a Phase 50 blocker for the developer to resolve BEFORE Plan 05 runs
> - This is the correct semantics of D-50-13 HARD pass: a real blocker, not a rationalized "deferred to CI" path

**FLAGGED: Phase 50 cannot HARD-pass D-50-13 cross-target clippy on this dev host as-is.** The developer must install:

1. **For `x86_64-unknown-linux-gnu`:** an `x86_64-linux-gnu-gcc` toolchain on the Windows host. Standard options:
   - WSL2 with `gcc-x86-64-linux-gnu` package
   - MSYS2 with `mingw-w64-cross-x86_64-linux-gnu-gcc`
   - Or move Plan 05 Task 3 verification to a Linux runner / CI lane (which is the "Outcome B" deferral the planner specifically chose to reject per Codex R-50-04).

2. **For `x86_64-apple-darwin`:** a Mac OS X SDK + `osxcross` toolchain on Windows. This is fundamentally a niche cross-compile and effectively requires:
   - A real macOS dev host or runner for the HARD-pass verification.

The Plan 05 planner needs to choose between (a) installing the cross-toolchains locally, or (b) reopening the "Outcome B" deferral that R-50-04 explicitly rejected. This decision is out of Plan 01's scope; it is recorded here so Plan 05's executor sees it before starting.

## Task 1 Audit Trail

### `cargo tree -p nono-cli --depth 1` diff (before vs after Cargo.toml edit)

```
> ├── async-trait v0.1.89 (proc-macro)
> ├── bytes v1.11.1
> ├── futures v0.3.32
> ├── sigstore-trust-root v0.7.0
> ├── tough v0.22.0
```

Exactly +5 new direct edges; no other additions, no version drift, no feature drift. All five crates were already resolved transitively in Cargo.lock at the planned versions.

### Cargo.lock diff analysis

```
diff --git a/Cargo.lock b/Cargo.lock
@@ -2264,7 +2264,9 @@ dependencies = [
 name = "nono-cli"
 version = "0.53.0"
 dependencies = [
+ "async-trait",
  "aws-lc-rs",
+ "bytes",
  ...
+ "futures",
  ...
+ "sigstore-trust-root",
  ...
+ "tough",
```

The lockfile shows a 5-line diff, but **all 5 entries are additions to the existing `[[package]] nono-cli` `dependencies` array** — no new `[[package]]` blocks, no version changes, no feature flag changes. This is the deterministic consequence of converting 5 transitive edges to direct edges.

**Rule 3 deviation note on plan acceptance criterion drift:** The plan stated "`git diff Cargo.lock` produces no output (lockfile unchanged — all 5 crates were already resolved transitively)". Strictly interpreted, this criterion is unachievable for ANY direct-dep promotion of an already-resolved crate — Cargo always materializes direct-dep edges in the consumer's `dependencies` array regardless of the underlying package set. The intent of the threat-model invariant T-50-01-01 ("All 5 promotions correspond to existing transitive edges, so lockfile content is invariant") IS preserved on the substantive dimensions: zero new packages, zero version changes, zero feature changes. The 5-line dep-list expansion is the only conforming outcome.

### Workspace MSRV check

```
$ grep '^rust-version' Cargo.toml
rust-version = "1.95"
```

Workspace MSRV at 1.95 already exceeds ureq 3.3.0's `rust-version = 1.85`. No bump needed; RESEARCH.md Open Question 4 closed.

## Tasks 2 + 3 Audit Trail

### Module declaration placement

```
crates/nono-cli/src/main.rs:93: mod trust_keystore;
crates/nono-cli/src/main.rs:94: mod trust_refresh;   ← NEW
crates/nono-cli/src/main.rs:95: mod trust_scan;
```

Alphabetical position correct (trust_keystore < trust_refresh < trust_scan). No `#[cfg(...)]` gate per D-50-11 (single cross-platform code path).

### Skeleton function signature

```rust
crates/nono-cli/src/trust_refresh.rs:58:
pub async fn refresh_production_trusted_root() -> Result<TrustedRoot> {
```

Matches plan acceptance grep `^pub async fn refresh_production_trusted_root\(\) -> Result<TrustedRoot>` exactly.

### R-50-02 hygiene check

```
$ grep -c 'TrustedRoot::production()' crates/nono-cli/src/trust_refresh.rs
0
```

Zero occurrences of the literal `TrustedRoot::production()` string in the new module — Plan 03's setup.rs-scoped grep cannot be tripped from this file.

### D-50-11 single cross-platform code path check

```
$ grep -c '#\[cfg(target_os' crates/nono-cli/src/trust_refresh.rs
0
```

No cfg gates; single code path.

## Verification

| Check | Expected | Actual | Pass |
|-------|----------|--------|------|
| `cargo build -p nono-cli` | exit 0 | exit 0 | ✓ |
| `cargo clippy -p nono-cli --no-deps -- -D warnings -D clippy::unwrap_used` (host triple x86_64-pc-windows-msvc) | exit 0 | exit 0 | ✓ |
| `cargo tree -p nono-cli --depth 1 \| grep -cE '^├── (tough\|sigstore-trust-root\|async-trait\|bytes\|futures) v'` | 5 | 5 | ✓ |
| `cargo check --workspace --target x86_64-unknown-linux-gnu` | exit 0 (D-50-13 pre-flight) | exit 101 | ✗ (FLAGGED — see Task 0 above) |
| `cargo check --workspace --target x86_64-apple-darwin` | exit 0 (D-50-13 pre-flight) | exit 101 | ✗ (FLAGGED — see Task 0 above) |
| `cargo tree -p nono-cli` diff: only +5 direct edges | yes | yes | ✓ |
| `git diff Cargo.lock` content invariant (packages/versions/features) | invariant | invariant (5-line dep-list expansion only) | ✓ (see Rule 3 note above) |
| Plan 02/03 stable symbol path `crate::trust_refresh::refresh_production_trusted_root` reachable | yes | yes | ✓ |

## Deviations from Plan

### Rule 3 (auto-fix blocking issue) — `sigstore-verify` import path drift

- **Found during:** Task 3 first build
- **Issue:** The plan instructed `use sigstore_verify::trust_root::TrustedRoot;` and signature `-> nono::Result<sigstore_verify::trust_root::TrustedRoot>`. But `sigstore-verify` is not a direct dep of `nono-cli` (it flows in only transitively through `nono`), so `use sigstore_verify::...` fails compile with `unresolved module or unlinked crate`.
- **Fix:** Switched to the canonical re-export path `use nono::trust::TrustedRoot;` (defined at `crates/nono/src/trust/bundle.rs:32` as `pub use sigstore_verify::trust_root::TrustedRoot;`). This is functionally identical and is in fact the same approach that the current `setup.rs:849` line uses (`nono::trust::TrustedRoot::production()`). The signature `Result<TrustedRoot>` matches the plan's acceptance grep verbatim.
- **Files modified:** `crates/nono-cli/src/trust_refresh.rs`
- **Commit:** `bebb3dc6`

### Rule 3 (auto-fix blocking issue) — strict-clippy dead_code on bin-crate skeleton

- **Found during:** Task 3 strict clippy
- **Issue:** The skeleton `pub async fn refresh_production_trusted_root` is unused by anything in the bin crate until Plan 03 swaps the call site. In a `bin` crate, `pub` items still trigger the `dead_code` lint when nothing else in the binary calls them. The plan's verification command `cargo clippy -p nono-cli --no-deps -- -D warnings -D clippy::unwrap_used` is required to exit 0; without intervention it fails on the dead_code lint.
- **Fix:** Added `#[allow(dead_code)]` directly above the skeleton function with a 4-line comment explaining the Wave-0 intent and the Plan-03 removal point. This is well-precedented in nono-cli (17 existing files already use the pattern) and matches the "skeleton signal" idiom. The cleaner alternative (a one-liner skeleton test) is blocked by the plan's explicit constraint: "No `#[cfg(test)] mod tests {}` block yet — Plan 04 adds tests."
- **Files modified:** `crates/nono-cli/src/trust_refresh.rs`
- **Commit:** `bebb3dc6`

### Rule 1 (interpretation correction) — Cargo.lock invariant phrasing

- **Found during:** Task 1 verification
- **Issue:** The plan's acceptance criterion "`git diff Cargo.lock` produces no output (lockfile unchanged — all 5 crates were already resolved transitively)" is unachievable in the literal byte-for-byte sense for any direct-dep promotion. Cargo unconditionally materializes the consumer crate's `dependencies = [...]` array entries when an edge becomes direct, regardless of the underlying package set state.
- **Fix:** Documented the substantive invariant interpretation: zero new packages, zero version changes, zero feature changes. The lockfile diff is exactly the 5-line `dependencies` array expansion. This matches the threat-model T-50-01-01 invariant precisely.
- **Files modified:** None (documentation-only deviation)
- **Commit:** N/A (recorded in this SUMMARY)

### Task batching — Tasks 2 + 3 in a single commit

- **Found during:** Task 2 commit boundary
- **Issue:** Committing Task 2 alone (the `mod trust_refresh;` declaration) would leave the workspace in a non-compiling state — a "broken commit" between Task 2 and Task 3 violates the atomicity contract that each commit should pass `cargo build`. The plan's Task 2 acceptance note explicitly anticipates this: "`cargo build -p nono-cli` exits 0 (because Task 3 creates the file)".
- **Fix:** Committed Tasks 2 and 3 together as `bebb3dc6`. The unified commit honors the atomicity invariant and the plan's stated coupling.
- **Files modified:** Two files in one commit (`main.rs` + `trust_refresh.rs`).
- **Commit:** `bebb3dc6`

## Phase 50 Blockers Raised

**BLOCKER-50-01:** Cross-target `cargo check` fails on the Windows dev host due to missing system C cross-compilers (`x86_64-linux-gnu-gcc` for Linux, `cc` for macOS). The rustup rust-std targets ARE installed; the gap is in the backing C toolchain that `cc-rs` requires to compile native dependencies (likely `aws-lc-rs`, `ring`, or similar).

**Impact:** Plan 05 Task 3's HARD cross-target clippy pass (per D-50-13) is mechanically unachievable on this dev host. The Plan 05 planner must decide:

1. Install the cross-toolchains locally (WSL2 + gcc-x86-64-linux-gnu for Linux; osxcross + macOS SDK for macOS). The macOS option in particular is awkward on a Windows host.
2. Move Plan 05 Task 3 verification to a Linux / macOS runner or CI lane. **This is the "Outcome B" deferral that R-50-04 explicitly rejected**, and reopening it requires a CONTEXT.md update to revise D-50-13's HARD-pass commitment to PARTIAL.

**Out-of-scope for Plan 01.** Recorded here so the Plan 05 executor sees it before starting Task 3.

## R-50-01 Closure

Codex R-50-01 finding: Plan 02 imports `sigstore_trust_root::{PRODUCTION_TUF_ROOT, DEFAULT_TUF_URL, TRUSTED_ROOT_TARGET}`, plus `#[async_trait]`, `bytes::Bytes`, and `futures::stream`, which all require direct-dep declarations in `nono-cli/Cargo.toml` (transitive availability is insufficient — Rust does not let downstream code `use` an unlinked transitive crate).

**Status: CLOSED.** All four sibling crates plus `tough` are now direct deps; `cargo tree -p nono-cli --depth 1` shows the 5 new edges. Plan 02 imports will resolve.

## R-50-02 Closure

Codex R-50-02 finding: If the skeleton module docs include the literal string `TrustedRoot::production()`, Plan 03's setup.rs-scoped grep at acceptance time becomes impossible to satisfy when it sweeps the broader codebase.

**Status: CLOSED.** Module docs use "upstream production helper" and "upstream call" phrasing instead. `grep -c 'TrustedRoot::production()' crates/nono-cli/src/trust_refresh.rs` returns 0.

## R-50-04 Closure

Codex R-50-04 finding: Plan 05's Outcome B (deferral of cross-target clippy to CI) contradicts D-50-13's HARD-pass commitment. Planner chose Option 3 (pre-flight install in Plan 01 Task 0).

**Status: PARTIALLY CLOSED.** Rustup targets confirmed installed and idempotent. Smoke `cargo check` on both Unix triples failed due to missing system C cross-toolchains (see BLOCKER-50-01). The Plan 05 planner must resolve this before Task 3 can HARD-pass; if the cross-toolchains cannot be installed locally, Codex R-50-04 reopens and D-50-13 must be revised to PARTIAL.

## Stable Symbol for Wave 1

Plans 02 and 03 can begin parallel work against:

```rust
crate::trust_refresh::refresh_production_trusted_root() -> nono::Result<nono::trust::TrustedRoot>
```

- **Plan 02** replaces the stub body with the real tough + ureq chain-walk (~150 lines production code + ~200 lines tests in Plan 04).
- **Plan 03** swaps the call site in `crates/nono-cli/src/setup.rs:849` from `nono::trust::TrustedRoot::production()` to `rt.block_on(crate::trust_refresh::refresh_production_trusted_root())`.

The async signature is the RESEARCH.md A4 correction to CONTEXT.md — the existing `tokio::runtime::Builder::new_current_thread()` block at `setup.rs:844-848` MUST be preserved.

## Self-Check: PASSED

- File `crates/nono-cli/src/trust_refresh.rs` exists: FOUND
- File `crates/nono-cli/src/main.rs` modified (line 94 `mod trust_refresh;`): FOUND
- File `crates/nono-cli/Cargo.toml` modified (5 new direct deps): FOUND
- Commit `9c8b9244`: FOUND
- Commit `bebb3dc6`: FOUND
- `cargo build -p nono-cli` exit 0: VERIFIED
- `cargo clippy -p nono-cli --no-deps -- -D warnings -D clippy::unwrap_used` exit 0: VERIFIED
- 5 new direct edges in `cargo tree -p nono-cli --depth 1`: VERIFIED
- Zero occurrences of `TrustedRoot::production()` in skeleton file: VERIFIED
- Zero `#[cfg(target_os` in skeleton file: VERIFIED
- D-50-13 cross-target HARD pass: FLAGGED as BLOCKER-50-01 (system C cross-toolchains absent on dev host; rustup targets ARE installed)
