# Phase 50: Corp-network TUF refresh via OS root store - Pattern Map

**Mapped:** 2026-05-21
**Files analyzed:** 6 (1 new module + 4 modified + 1 new fixture dir)
**Analogs found:** 6 / 6 (all in-tree)

> **Critical research note carried forward (RESEARCH.md §Summary, A4):** `tough::Transport::fetch`, `tough::RepositoryLoader::load`, `tough::Repository::read_target`, and `IntoVec::into_vec` are ALL `async`. CONTEXT.md's claim "`tough` + `ureq` are sync, no tokio runtime needed" is **wrong** — the planner MUST preserve the `tokio::runtime::Builder::new_current_thread()` block at `crates/nono-cli/src/setup.rs:844-848`. All patterns below assume the new module exposes an `async fn refresh_production_trusted_root() -> nono::Result<TrustedRoot>` called via `rt.block_on(...)`.

## File Classification

| New/Modified File                                                  | Role        | Data Flow                              | Closest Analog                                                                 | Match Quality |
|--------------------------------------------------------------------|-------------|----------------------------------------|--------------------------------------------------------------------------------|---------------|
| `crates/nono-cli/src/trust_refresh.rs` (NEW, ~150 prod + ~200 test)| module (TUF chain-walk + transport impl) | request-response (HTTP fetch loop + async transform → TrustedRoot value) | **structural:** `crates/nono-cli/src/setup.rs:888-919` (`from_file_step`) for step-shape; **upstream port:** `sigstore-trust-root-0.7.0/src/tuf.rs:349-407` (`TufClient::load_repository`) for chain-walk body | role-match (in-tree); exact (upstream port) |
| `crates/nono-cli/src/setup.rs` lines 828-868 (`refresh_trust_root_step` body) | pipeline step | request-response (delegates to `trust_refresh::*`)             | `crates/nono-cli/src/setup.rs:888-919` (`from_file_step` — sibling step in same file) | exact |
| `crates/nono-cli/src/main.rs` (add `mod trust_refresh;`)           | module decl | static                                  | `crates/nono-cli/src/main.rs:80` (`mod setup;`); `:87` (`mod trust_cmd;`); `:93` (`mod trust_keystore;`); `:94` (`mod trust_scan;`) | exact |
| `crates/nono-cli/Cargo.toml` (add `tough = "0.22"`)                | manifest    | static                                  | `crates/nono-cli/Cargo.toml:73` (`ureq` declaration block — same dependency group) | role-match |
| `crates/nono-cli/tests/fixtures/tuf-repo-{happy,bad-sig,malformed}/*.json` (NEW) | test fixture | static                                  | `crates/nono/tests/fixtures/trust-root-frozen.json` (Phase 32/49 fixture; in-tree precedent for checked-in JSON fixture) | role-match |
| `docs/cli/development/windows-poc-handoff.mdx`                     | doc         | n/a                                     | Same file lines 157-244 (Phase 49 `--from-file` update — the prior in-tree edit of this same section) | exact |

## Pattern Assignments

### `crates/nono-cli/src/trust_refresh.rs` (NEW module — TUF chain-walk + UreqTransport)

> Two analogs apply: (1) the in-tree **step-shape** mirror is `from_file_step`, but only the calling step in `setup.rs` consumes that. (2) The module BODY is a direct port of upstream `sigstore-trust-root-0.7.0/src/tuf.rs::TufClient::load_repository` (verbatim shape — RESEARCH.md §"Architecture Patterns" Pattern 3, lines 309-376). The planner copies the upstream shape with TWO substitutions (transport + datastore path) as documented in 50-RESEARCH.md.

**Imports pattern** (mirror `crates/nono-cli/src/setup.rs:1-7` style — use of `nono::{NonoError, Result}` as the canonical error/result imports for nono-cli production modules):

```rust
// Source: crates/nono-cli/src/setup.rs:1-7 — canonical nono-cli module preamble
use crate::cli::SetupArgs;
use crate::profile;
use nono::{NonoError, Result};
use std::fs;
use std::path::Path;
```

The new module SHOULD use the same `nono::{NonoError, Result}` import (NOT `crate::error::*` — see RESEARCH.md §Pattern 3 example line 318 which uses `use crate::error::{NonoError, Result}`; that import path does NOT exist in nono-cli, so the planner must substitute it with `use nono::{NonoError, Result}` to match in-tree convention).

**`NonoError::Setup(format!(...))` wrapping** (lines from `setup.rs:847-855` AND `setup.rs:858`):

```rust
// Source: crates/nono-cli/src/setup.rs:847-855 — the EXACT wrapping convention to copy
let trusted_root = rt
    .block_on(nono::trust::TrustedRoot::production())
    .map_err(|e| {
        NonoError::Setup(format!(
            "Failed to fetch Sigstore trusted root from \
             https://tuf-repo-cdn.sigstore.dev: {e}"
        ))
    })?;

// Source: crates/nono-cli/src/setup.rs:858 — single-line variant for serialization
let json = serde_json::to_string_pretty(&trusted_root)
    .map_err(|e| NonoError::Setup(format!("serialize trusted root: {e}")))?;
```

**Convention confirmed by Grep**: every `NonoError::Setup(format!(...))` call site across nono-cli (30+ matches in `exec_strategy_windows/*.rs`, `setup.rs`) uses the `"<verb-phrase>: {e}"` shape — short snake-cased verb phrase, colon, error display. The new module follows this verbatim. Suggested wraps per RESEARCH.md §"Architecture Patterns" Pattern 3:

- `NonoError::Setup(format!("invalid Sigstore TUF URL: {e}"))`
- `NonoError::Setup(format!("invalid Sigstore targets URL: {e}"))`
- `NonoError::Setup(format!("create tuf-cache dir {}: {e}", datastore_dir.display()))`
- `NonoError::Setup(format!("Sigstore TUF refresh failed: {e}"))`  ← keeps the verb of the existing `refresh_trust_root_step` error so user-visible text stays close to the current message
- `NonoError::Setup(format!("read trusted_root target: {e}"))`
- `NonoError::Setup(format!("collect trusted_root bytes: {e}"))`
- `NonoError::Setup(format!("trusted_root.json is not UTF-8: {e}"))`
- `NonoError::Setup(format!("parse trusted_root.json: {e}"))`

**Test module placement (`#[cfg(test)] mod tests`)** — `crates/nono-cli/src/setup.rs:1277-1332`:

```rust
// Source: crates/nono-cli/src/setup.rs:1277-1332 — canonical co-located test module
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_setup_profiles_loadable_by_name() {
        let _guard = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        let tmp = tempdir().expect("tempdir");

        // Point HOME at a tmpdir so both setup and loader derive paths
        // under our control.
        let _env = crate::test_env::EnvVarGuard::set_all(&[
            ("HOME", tmp.path().to_str().expect("tmp path")),
            ("XDG_CONFIG_HOME", "__placeholder__"),
        ]);
        _env.remove("XDG_CONFIG_HOME");
        // ... body ...
    }
}
```

Key conventions for new tests in `trust_refresh.rs`:

1. **Async tests:** because `refresh_production_trusted_root` is `async fn`, tests that call it use `#[tokio::test]` (NOT `#[test]` — Grep confirmed there are zero existing `#[tokio::test]` examples in `nono-cli/src/**`, so the new module ESTABLISHES this pattern within nono-cli's src tree; outside the src tree there is precedent in `crates/nono-cli/tests/*`). Planner: confirm `tokio` features in `Cargo.toml:71` include enough for `#[tokio::test]` (`rt` is present; `macros` may need adding).
2. **`crate::test_env::ENV_LOCK`** acquired at test start (line 1291-1294 shape) — REQUIRED whenever the test mutates `HOME` / `NONO_TEST_HOME` (Phase 50 tests DO set `NONO_TEST_HOME` to control the `tuf-cache` directory location). CLAUDE.md §Coding Standards explicitly calls this out as the project convention.
3. **`crate::test_env::EnvVarGuard::set_all(&[...])`** for env var save/restore (line 1302-1305 shape).
4. **`tempfile::tempdir()` + `.expect("tempdir")`** — `expect` is allowed in `#[cfg(test)]` code (`#[allow(clippy::unwrap_used)]` is the test-module exception per CLAUDE.md).

**`StaticMapTransport` test fixture loader** (RESEARCH.md §"Code Examples" Example C, with in-tree fixture path mirroring `crates/nono-cli/tests/setup_trust_root.rs:420-427`):

```rust
// Source pattern: crates/nono-cli/tests/setup_trust_root.rs:418-427 — frozen-fixture path resolver
fn fixture_dir(name: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}
```

Note: existing fixture lives in `crates/nono/tests/fixtures/trust-root-frozen.json` and is reached from `nono-cli/tests/*.rs` via `..\nono\tests\fixtures\` traversal. Phase 50 fixtures live INSIDE `crates/nono-cli/tests/fixtures/{tuf-repo-happy,tuf-repo-bad-sig,tuf-repo-malformed}/`, so no `..` traversal is needed — keep the path inside the crate to match the directory already scaffolded (`crates/nono-cli/tests/fixtures/.gitkeep` exists).

---

### `crates/nono-cli/src/setup.rs` lines 828-868 (`refresh_trust_root_step` body modification)

**Analog:** `crates/nono-cli/src/setup.rs:888-919` (`from_file_step` — SAME FILE, sibling step). The new body is the MINIMUM modification of the current `refresh_trust_root_step` — keep header, cache-dir creation, runtime build, write, and success-print verbatim; ONLY the `rt.block_on(...)` argument changes.

**Step-shape skeleton both functions share** (extracted by direct diff of lines 828-868 vs 888-919):

```rust
// SHARED SKELETON (verbatim from setup.rs:828-868 with from_file_step:888-919 confirming the pattern):

// 1) Cache dir creation — IDENTICAL between both steps
let cache_dir = crate::config::nono_home_dir()?
    .join(".nono")
    .join("trust-root");
std::fs::create_dir_all(&cache_dir).map_err(NonoError::Io)?;

// 2) Header print — both use [phase_index/total_phases] header
println!(
    "[{}/{}] <verb-phrase>...",
    self.refresh_trust_root_phase_index(),
    self.total_phases()
);

// 3) Body (refresh_trust_root_step CURRENT body — to be replaced):
//    BUILD tokio runtime, BLOCK_ON the chain walk, WRAP error.
//    The runtime build STAYS (tough is async — RESEARCH.md A4 correction).

// 4) Compute cache_path and write
let cache_path = cache_dir.join("trusted_root.json");
std::fs::write(&cache_path, &json).map_err(NonoError::Io)?;
// or for from_file_step: std::fs::copy(src, &cache_path) with best-effort cleanup on Err

// 5) Trailing success-print — identical shape
println!(
    "  * Sigstore trusted root cached at {}",
    cache_path.display()
);
println!();
Ok(())
```

**Target body** (RESEARCH.md §Pattern 4 lines 424-459 — 3-line diff from current):

```rust
// Source: setup.rs:828-868 current implementation with the single body change
fn refresh_trust_root_step(&self) -> Result<()> {
    let cache_dir = crate::config::nono_home_dir()?
        .join(".nono")
        .join("trust-root");
    std::fs::create_dir_all(&cache_dir).map_err(NonoError::Io)?;

    println!(
        "[{}/{}] Refreshing Sigstore trusted root...",
        self.refresh_trust_root_phase_index(),
        self.total_phases()
    );

    // tough + ureq drive an async API; preserve the one-shot tokio runtime.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| NonoError::Setup(format!("tokio runtime: {e}")))?;
    let trusted_root = rt
        .block_on(crate::trust_refresh::refresh_production_trusted_root())
        .map_err(|e| {
            NonoError::Setup(format!(
                "Failed to fetch Sigstore trusted root from \
                 https://tuf-repo-cdn.sigstore.dev: {e}"
            ))
        })?;

    let json = serde_json::to_string_pretty(&trusted_root)
        .map_err(|e| NonoError::Setup(format!("serialize trusted root: {e}")))?;
    let cache_path = cache_dir.join("trusted_root.json");
    std::fs::write(&cache_path, &json).map_err(NonoError::Io)?;

    println!(
        "  * Sigstore trusted root cached at {}",
        cache_path.display()
    );
    println!();
    Ok(())
}
```

**Differences from `from_file_step`** (informational; planner does NOT need to mirror these — they apply to the from-file path only):

- `from_file_step` has `#[allow(clippy::wrong_self_convention)]` (line 887) because of its `from_` prefix; the new `refresh_trust_root_step` does NOT need this.
- `from_file_step` calls `nono::trust::bundle::load_trusted_root(src)` + `nono::trust::bundle::check_trusted_root_freshness(...)` for validation BEFORE writing; `refresh_trust_root_step` skips this because tough's chain walk + sigstore-trust-root's `TrustedRoot::from_json` ALREADY validate the bytes during the chain-walk.
- `from_file_step` uses `std::fs::copy(src, &cache_path)` with `let _ = std::fs::remove_file(&cache_path)` cleanup-on-error (lines 924-927); `refresh_trust_root_step` uses `std::fs::write(&cache_path, &json)` directly (the bytes have already been freshly serialized via `to_string_pretty`).

**D-49-B2 best-effort cleanup pattern** to apply INSIDE `trust_refresh::refresh_production_trusted_root` if the chain walk fails after `tuf-cache/` is created:

```rust
// Source: setup.rs:924-927 (from_file_step cleanup) — the D-49-B2 pattern
if let Err(e) = std::fs::copy(src, &cache_path) {
    let _ = std::fs::remove_file(&cache_path);
    return Err(NonoError::Io(e));
}
```

For Phase 50, the analog is per-RESEARCH.md §Pattern 3 lines 350-354:

```rust
.map_err(|e| {
    // D-49-B2 best-effort cleanup: remove tuf-cache on failure to avoid
    // partial state. The `let _ =` ignores the cleanup result because the
    // primary error is what surfaces to the user.
    let _ = std::fs::remove_dir_all(&datastore_dir);
    NonoError::Setup(format!("Sigstore TUF refresh failed: {e}"))
})?;
```

---

### `crates/nono-cli/src/main.rs` (add `mod trust_refresh;`)

**Analog:** `crates/nono-cli/src/main.rs:80,87,93,94` (existing `mod setup; mod trust_cmd; mod trust_keystore; mod trust_scan;` declarations).

**Imports pattern** (lines 80, 87, 93-94 — alphabetical ordering inside the `trust_*` cluster):

```rust
// Source: crates/nono-cli/src/main.rs:80,87,93-94 — existing module declarations
mod setup;
// ...
mod trust_cmd;
#[cfg(not(target_os = "windows"))]
mod trust_intercept;
#[cfg(target_os = "windows")]
#[path = "trust_intercept_windows.rs"]
mod trust_intercept;
mod trust_keystore;
mod trust_scan;
```

**Insertion site:** between `mod trust_intercept;` (line 92) and `mod trust_keystore;` (line 93), preserving alphabetical order:

```rust
mod trust_intercept;
// (existing windows variant)
mod trust_keystore;
mod trust_refresh;      // ← NEW (alphabetical: comes after trust_keystore? — NO; r < s, so it goes BEFORE trust_scan)
mod trust_scan;
```

Wait — alphabetical: `trust_cmd` < `trust_intercept` < `trust_keystore` < `trust_refresh` < `trust_scan`. So the new line goes AFTER `mod trust_keystore;` (line 93) and BEFORE `mod trust_scan;` (line 94). No `#[cfg(...)]` gate — D-50-11 specifies a single cross-platform code path.

---

### `crates/nono-cli/Cargo.toml` (add `tough = "0.22"`)

**Analog:** `crates/nono-cli/Cargo.toml:68-75` block (existing sigstore + transport dep cluster):

```toml
# Source: crates/nono-cli/Cargo.toml:64-75 — existing dep cluster the new `tough` belongs in
# Keyless (Sigstore/Fulcio/Rekor) signing for instruction file attestation
# Phase 37 Plan 37-06: bumped 0.6.5 → 0.7.0 alongside sigstore-verify 0.7.0
sigstore-sign = "0.7.0"
# YAML-merge directive support (Plan 36-02; upstream-aligned at v0.10.0 per 242d4917)
serde_yaml_ng = "=0.10.0"
tokio = { version = "1", features = ["rt", "net", "io-util"] }

ureq = { version = "3", features = ["platform-verifier"] }
semver = "1"
regress = "0.11"
```

**Convention observed:**

- Deps are NOT strictly alphabetical (e.g., `tokio` comes after `serde_yaml_ng`, `ureq` after `tokio`).
- Each non-trivial dep gets a 1-3 line `#` comment above explaining WHY it's there (phase reference + functional purpose). Examples: lines 63-67 (sigstore-sign), lines 69 (serde_yaml_ng), implicit `# ...` patterns throughout.
- The `[dependencies]` block (line 42) ends at line 87; `[target.'cfg(...)'.dependencies]` starts at line 89.

**Insertion (recommended placement: immediately above `ureq` at line 73, grouping it with the sigstore+transport stack):**

```toml
# Phase 50 D-50-05: promoted from transitive (via sigstore-trust-root 0.7.0 →
# tough 0.22.0 in Cargo.lock) to direct dep so we can call
# `tough::RepositoryLoader` with our own `Transport` impl that consults the
# Windows certificate store. Version pin matches the existing lockfile entry
# to avoid a second copy.
tough = "0.22"

ureq = { version = "3", features = ["platform-verifier"] }
```

**MSRV verification** (RESEARCH.md §"Environment Availability" footnote): ureq 3.3.0 declares `rust-version = "1.85"`. Planner runs `grep rust-version Cargo.toml` to confirm workspace MSRV is ≥ 1.85 before adding `tough`; if MSRV is still 1.77, bump workspace `Cargo.toml`'s `rust-version` first (this is the same pattern Phase 04 plan 02 used).

**Cargo.toml dependency add validation** (RESEARCH.md §Standard Stack lines 117-145 cargo-tree diff procedure):

```bash
cargo tree -p nono-cli --depth 1 | sort > /tmp/tree-before
# (edit Cargo.toml — add `tough = "0.22"`)
cargo tree -p nono-cli --depth 1 | sort > /tmp/tree-after
diff /tmp/tree-before /tmp/tree-after
# Expected: only `+tough v0.22.0` line; no other additions.
```

---

### `crates/nono-cli/tests/fixtures/tuf-repo-{happy,bad-sig,malformed}/*.json` (NEW test fixtures)

**Analog:** `crates/nono/tests/fixtures/trust-root-frozen.json` — the existing in-tree precedent for checked-in JSON trust fixtures. (Reached via `..\nono\tests\fixtures\` from `nono-cli/tests/*` per `crates/nono-cli/tests/setup_trust_root.rs:420-427`.)

**Layout convention** observed across the workspace:

- Test fixtures live at `crates/<crate>/tests/fixtures/<name>.json` (flat JSON file) — example: `crates/nono/tests/fixtures/trust-root-frozen.json`.
- For Phase 50, fixtures are MULTI-FILE TUF repos (1.root.json, 2.root.json, timestamp.json, snapshot.json, targets.json, trusted_root.json), so a subdirectory is needed per fixture variant:
  - `crates/nono-cli/tests/fixtures/tuf-repo-happy/`
  - `crates/nono-cli/tests/fixtures/tuf-repo-bad-sig/`
  - `crates/nono-cli/tests/fixtures/tuf-repo-malformed/`
- The `crates/nono-cli/tests/fixtures/.gitkeep` already exists, so this directory is established as the fixture root for nono-cli.

**Generation method** (RESEARCH.md §"Code Examples" Example C and §"Open Questions" Q3): two options — planner picks.

1. **Pre-generated via `tuftool` (Bottlerocket TUF CLI, NOT installed locally; RESEARCH.md §"Environment Availability" notes this) and committed JSON files** — simplest test-time path; recommended by RESEARCH.md.
2. **Programmatic generation via `tough::editor::RepositoryEditor` at test-time** — more flexible but adds runtime test cost.

**Fixture loader** (verbatim shape from `crates/nono-cli/tests/setup_trust_root.rs:420-427`):

```rust
// Source pattern: crates/nono-cli/tests/setup_trust_root.rs:418-427 — fixture path resolver
fn load_fixture(name: &str) -> HashMap<String, Vec<u8>> {
    let fixture_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    let mut map = HashMap::new();
    for entry in std::fs::read_dir(&fixture_dir).expect("read fixture dir") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name().into_string().expect("utf-8 filename");
        let bytes = std::fs::read(entry.path()).expect("read fixture file");
        map.insert(name, bytes);
    }
    map
}
```

(In `#[cfg(test)]` code, `.expect(...)` is permitted — CLAUDE.md exception. The existing in-tree fixture loader at `setup_trust_root.rs:421-427` confirms the `env!("CARGO_MANIFEST_DIR")` + `.join("tests").join("fixtures")` shape.)

---

### `docs/cli/development/windows-poc-handoff.mdx` (doc update — reframe `--from-file`)

**Analog:** `docs/cli/development/windows-poc-handoff.mdx:157-244` — the existing "Sigstore Trust Root Setup" section that Phase 49 last edited. THIS IS THE EXACT SECTION TO UPDATE.

**Current shape** (lines 166-174 — the Path A / Path B framing introduced in Phase 49):

```mdx
Run once after install (pick ONE — Path A for network-reachable hosts, Path B with `--from-file` for offline / network-restricted hosts):

```powershell
# Path A — network-reachable host (fetches from https://tuf-repo-cdn.sigstore.dev):
nono setup --refresh-trust-root

# Path B — offline host (download the trusted_root.json release asset, then):
nono setup --from-file C:\path\to\downloaded\trusted_root.json
```

Path B is also the recovery path when Path A fails with a stale-embedded-anchor
error — see the Known issue section below.
```

**Phase 50 reframe direction** (per CONTEXT.md `<specifics>` and `<decisions>` Discretion bullet 3):

- v0.53.x+ note: Path A succeeds natively on Windows corp-network hosts (whose enterprise CA is in the Windows root store) — the TLS-inspecting-proxy failure documented in `.planning/debug/resolved/sigstore-tuf-fetch-transport.md` is RESOLVED in v0.53.x+ because the HTTP client now consults the Windows certificate store via `ureq + platform-verifier`.
- `--from-file` is reframed: from "for corp-network failures" → to "for hosts with no outbound network at all" (true air-gapped / offline POC hosts).
- "Known issue: Sigstore TUF root rotation" (lines 188-244) — Phase 50 does NOT fix the rotation/stale-anchor failure mode; that remains a Phase 49 recovery path. UPDATE the wording so the reader knows Path A failures in v0.53.x+ are NO LONGER caused by corp-network TLS interception (the historic root cause has been eliminated), and the only remaining Path-A failure mode is the upstream sigstore-trust-root stale-anchor case.

**MDX heading convention** (line 188 — `#### Known issue: Sigstore TUF root rotation`): 4-hash heading (`####`) inside the trust-root H2 (`## Sigstore Trust Root Setup`). Maintain heading levels when inserting new content.

**Style convention** observed in lines 157-244:

- PowerShell fenced blocks: ` ```powershell ` (line 168).
- ASCII tables / structured callouts use `<Note>` / `<Warning>` MDX components (see lines 10-12 and 66-68).
- Phase references inline: "Phase 49", "Phase 32 D-32-01" (lines 184, 205).
- Cross-links to ADRs / planning files via relative paths: `(../../architecture/sigstore-tuf-cache.md)` (line 184).

Planner's choice: inline patch (a 3-5 line note added near line 174 indicating "as of v0.53.x+, Path A succeeds on corp-network hosts whose enterprise CA is in the Windows root store") is the minimum viable change; a small rewrite of lines 157-186 is also acceptable per CONTEXT.md Discretion bullet 3.

---

## Shared Patterns

### Authentication / Authorization

**Not applicable** — Phase 50 introduces no new auth surface. The TUF chain walk's "authentication" is signature verification (delegated entirely to `tough`); the HTTP client's "authentication" is TLS chain validation (delegated entirely to `rustls-platform-verifier` via `ureq`'s `platform-verifier` feature). nono provides zero crypto code.

### Error Handling

**Source:** `crates/nono-cli/src/setup.rs:828-868` (existing convention across all nono-cli setup-pipeline steps).
**Apply to:** every error path in `trust_refresh::refresh_production_trusted_root` and in the modified `refresh_trust_root_step`.

```rust
// Source: crates/nono-cli/src/setup.rs:847-855 — the convention applied 30+ times across nono-cli
.map_err(|e| NonoError::Setup(format!("<short verb phrase>: {e}")))?

// Examples from setup.rs:
//   tokio runtime:        line 847 — "tokio runtime: {e}"
//   serialize trusted...: line 858 — "serialize trusted root: {e}"
//   IO errors → NonoError::Io: line 832 — `.map_err(NonoError::Io)?`
```

**Convention summary** (confirmed by Grep over `crates/nono-cli/src/`):

- All textual setup errors → `NonoError::Setup(format!("<verb phrase>: {e}"))`.
- Filesystem `io::Error` → `.map_err(NonoError::Io)?` (no format wrapping; the `Io` variant preserves the underlying error).
- Display format: short lowercase verb phrase + colon + `{e}` (e.g., `"create tuf-cache dir {}: {e}"`, NOT `"Failed to create tuf-cache dir: {e}"`). Exception: the SINGLE user-visible top-level message at `setup.rs:851-854` ("Failed to fetch Sigstore trusted root from https://...") DOES use a longer descriptive phrase — preserve this verbatim because it appears in the corp-network UAT pass criteria (50-SPEC.md Req 6).

### Validation

**Not applicable as a new pattern** — validation flows through `tough` (TUF signature math) and `TrustedRoot::from_json` (schema validation), both upstream.

### Path Handling

**Source:** `crates/nono-cli/src/config/mod.rs:130` (`pub fn nono_home_dir() -> Result<PathBuf>`).
**Apply to:** the TUF datastore directory resolution in `trust_refresh::refresh_production_trusted_root`.

```rust
// Source: crates/nono-cli/src/config/mod.rs:130-135 — canonical home-dir resolver with NONO_TEST_HOME honor
pub fn nono_home_dir() -> Result<PathBuf> {
    if let Ok(value) = std::env::var("NONO_TEST_HOME") {
        let path = PathBuf::from(&value);
        if !path.is_absolute() {
            return Err(NonoError::EnvVarValidation { ... });
        }
        // ...
    }
}
```

**Convention:** ALWAYS go through `crate::config::nono_home_dir()` for any path under `<nono_home>/.nono/...`. This is the SAME function used at `setup.rs:829` and `setup.rs:889` (both `refresh_trust_root_step` and `from_file_step`), and it transparently honors `NONO_TEST_HOME` for test isolation. Phase 50's `<nono_home>/.nono/trust-root/tuf-cache/` resolution reuses it verbatim:

```rust
let datastore_dir = crate::config::nono_home_dir()?
    .join(".nono")
    .join("trust-root")
    .join("tuf-cache");
```

### Test Environment Isolation

**Source:** `crates/nono-cli/src/setup.rs:1291-1306` (the `ENV_LOCK` + `EnvVarGuard::set_all` pattern).
**Apply to:** every test in `trust_refresh::tests` that touches `NONO_TEST_HOME` / `HOME`.

```rust
// Source: crates/nono-cli/src/setup.rs:1291-1306 — env-isolation preamble for parallel test safety
let _guard = match crate::test_env::ENV_LOCK.lock() {
    Ok(g) => g,
    Err(p) => p.into_inner(),
};

let tmp = tempdir().expect("tempdir");

let _env = crate::test_env::EnvVarGuard::set_all(&[
    ("HOME", tmp.path().to_str().expect("tmp path")),
    ("NONO_TEST_HOME", tmp.path().to_str().expect("tmp path")),
]);
```

CLAUDE.md §Coding Standards specifically mandates this pattern: "Tests that modify `HOME`, `TMPDIR`, `XDG_CONFIG_HOME`, or other env vars must save and restore the original value. Rust runs unit tests in parallel within the same process, so an unrestored env var causes flaky failures."

### Async/Sync Bridging

**Source:** `crates/nono-cli/src/setup.rs:844-848` (existing one-shot tokio runtime in `refresh_trust_root_step`).
**Apply to:** the `refresh_trust_root_step` modification (preserved verbatim per A4 correction).

```rust
// Source: crates/nono-cli/src/setup.rs:844-848 — preserved verbatim (NOT eliminated, despite CONTEXT.md)
let rt = tokio::runtime::Builder::new_current_thread()
    .enable_all()
    .build()
    .map_err(|e| NonoError::Setup(format!("tokio runtime: {e}")))?;
let trusted_root = rt
    .block_on(crate::trust_refresh::refresh_production_trusted_root())
    .map_err(|e| { /* ... */ })?;
```

**Inside the async function**, sync `ureq` calls are bridged via `tokio::task::spawn_blocking` per RESEARCH.md §"Architecture Patterns" Pattern 1 (verbatim 30-line `UreqTransport::fetch` impl, lines 211-265 of 50-RESEARCH.md). The `spawn_blocking` future is `await`ed and its `JoinError` is converted to `TransportError::new_with_cause(TransportErrorKind::Other, url, e)`.

### CLI Phase-Step Header

**Source:** `crates/nono-cli/src/setup.rs:834-838` AND `:894-898` (identical shape between both steps).
**Apply to:** modified `refresh_trust_root_step` (already in place; planner preserves verbatim).

```rust
println!(
    "[{}/{}] <verb-phrase>...",
    self.refresh_trust_root_phase_index(),
    self.total_phases()
);
```

`<verb-phrase>` is `"Refreshing Sigstore trusted root"` (current step text — PRESERVED). The trailing `"..."` ellipsis is part of the convention. Followed at the end of the step by:

```rust
println!("  * Sigstore trusted root cached at {}", cache_path.display());
println!();
```

(Note the 2-space indent + asterisk bullet + trailing blank `println!()` — consistent between `refresh_trust_root_step:862-866` and `from_file_step:929-935`.)

---

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `crates/nono-cli/src/trust_refresh.rs` `UreqTransport` impl | `tough::Transport` adapter | streaming (HTTP request → byte stream) | No existing `tough::Transport` impls in the nono workspace (confirmed via `Grep("tough", glob="**/*.rs")` returns zero matches). The structural template is upstream-only: `tough-0.22.0/src/http.rs:142-150` (reference `HttpTransport` impl) and `sigstore-trust-root-0.7.0/src/tuf.rs:349-407` (port target). Planner copies these verbatim per RESEARCH.md §Pattern 1 (lines 211-265) and §Pattern 3 (lines 309-376), NOT from any in-tree analog. |
| `crates/nono-cli/src/trust_refresh.rs` `StaticMapTransport` test transport | test fixture HTTP transport | streaming (in-memory map → byte stream) | No existing test transport patterns in nono. Direct port from RESEARCH.md §"Code Examples" Example B (lines 588-624 of 50-RESEARCH.md). Inspired by `tough-0.22.0/tests/transport.rs:38-49` (upstream-only). |
| `crates/nono-cli/tests/fixtures/tuf-repo-{happy,bad-sig,malformed}/` test fixture content | TUF metadata bytes | static JSON | No existing multi-file JSON fixture trees in the workspace — `crates/nono/tests/fixtures/trust-root-frozen.json` is a single flat file. Planner is establishing a new fixture-directory pattern. Generation is via `tuftool` one-time (RESEARCH.md §"Code Examples" Example C option 1) or programmatic at test-time via `tough::editor` (option 2); planner picks. |

---

## Metadata

**Analog search scope:**
- `crates/nono-cli/src/**` (primary; in-tree step + module + error-wrap patterns)
- `crates/nono-cli/tests/**` (fixture-path + setup-mod-tests patterns)
- `crates/nono-cli/Cargo.toml` (dep-add convention)
- `crates/nono/tests/fixtures/` (in-tree JSON fixture precedent)
- `crates/nono/src/trust/bundle.rs` (cache contract — read-only reference, NOT modified)
- `crates/nono/src/config/mod.rs` (`nono_home_dir` resolver)
- `docs/cli/development/windows-poc-handoff.mdx` (doc-update target)
- `~/.cargo/registry/src/.../tough-0.22.0/**` (upstream port reference)
- `~/.cargo/registry/src/.../sigstore-trust-root-0.7.0/**` (upstream port reference)
- `~/.cargo/registry/src/.../ureq-3.3.0/**` (upstream agent-builder reference)

**Files scanned:** ~20 in-tree + 3 upstream crates (via RESEARCH.md cited line numbers).

**Pattern extraction date:** 2026-05-21

**Key cross-cutting reminder:** RESEARCH.md A4 (tough is async) is the single most important correction to CONTEXT.md. Every plan that touches `refresh_trust_root_step` MUST preserve the `tokio::runtime::Builder::new_current_thread()` block; this contradicts the CONTEXT.md `<code_context>` Integration Points sentence "Phase 50 ELIMINATES the only async call in `refresh_trust_root_step`". Planner: flag this correction in the wave-0 commit message and SUMMARY.md.

## PATTERN MAPPING COMPLETE
