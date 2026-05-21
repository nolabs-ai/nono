# Phase 50: Corp-network TUF refresh via OS root store — Research

**Researched:** 2026-05-21
**Domain:** TUF chain-walk + ureq v3 platform-verifier HTTP transport
**Confidence:** HIGH (all critical APIs verified against on-disk crate source)

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-50-01:** New sibling module at `crates/nono-cli/src/trust_refresh.rs`. `setup.rs::refresh_trust_root_step` delegates to it via a single function call. NOT moved into `crates/nono` library (P32-CHK-002 / D-32-15 HTTP-free invariant preserved).
- **D-50-02:** Public surface is a single free function: `pub fn refresh_production_trusted_root() -> nono::Result<sigstore_verify::trust_root::TrustedRoot>`. Swap-in replacement for `TrustedRoot::production()`.
- **D-50-03:** Tests colocated via `#[cfg(test)] mod tests {}`.
- **D-50-04:** `tough::RepositoryLoader` drives the chain walk. nono provides `struct UreqTransport(ureq::Agent)` impl `tough::Transport`. Hand-rolled signature verification REJECTED.
- **D-50-05:** `tough 0.22.0` promoted from transitive to direct dep of `nono-cli`. Version pin matches existing lockfile entry.
- **D-50-06:** Embedded v14 anchor sourced from `sigstore_trust_root::PRODUCTION_TUF_ROOT` const. No second copy in nono.
- **D-50-07:** TUF datastore at `<nono_home>/.nono/trust-root/tuf-cache/`. Created if missing. Best-effort cleanup on failure.
- **D-50-08:** Tests use `struct StaticMapTransport(HashMap<String, Vec<u8>>)` implementing `tough::Transport`. No localhost server.
- **D-50-09:** No real TLS handshake test in-phase. HUMAN-UAT on corp-network is dispositive.
- **D-50-10:** ≥ 4 tests: happy-path, bad-signature → `NonoError::Setup`, malformed-JSON → `NonoError::Setup`, byte-identical-cache snapshot.
- **D-50-11:** Single cross-platform code path. No `#[cfg(target_os = "windows")]` gate at call site.
- **D-50-12:** "Windows-only" = USER-IMPACT scope, not CODE-GATING. Linux corp-CA users auto-covered.
- **D-50-13:** CI clippy on x86_64-pc-windows-msvc + x86_64-unknown-linux-gnu + x86_64-apple-darwin is HARD pass (not partial).

### Claude's Discretion

- `NonoError` variant for tough errors → suggested `NonoError::Setup(format!("Sigstore TUF refresh failed: {e}"))`.
- `ureq::Agent` config knobs (timeout, retry, redirect) → researcher/planner picks reasonable defaults.
- Doc-update granularity for `windows-poc-handoff.mdx` → inline patch or small rewrite; acceptance is "describes v0.53.x+ corp-network refresh works natively".

### Deferred Ideas (OUT OF SCOPE)

- Upstream sigstore-rs PR adding `TrustedRoot::with_http_client(...)` seam (Surface (b)).
- Online freshness-probe with new HTTP client (Phase 32 D-32-03 future work).
- CI MITM proxy test rig.
- Linux corp-CA UX docs (auto-covered by D-50-11).
</user_constraints>

<phase_requirements>
## Phase Requirements (from 50-SPEC.md)

| ID | Description | Research Support |
|----|-------------|------------------|
| Req 1 | Nono-local TUF chain-walk replaces upstream `TrustedRoot::production()` call | `tough::RepositoryLoader::new(root_bytes, metadata_url, targets_url).transport(impl Transport).datastore(path).load().await` pattern verified at `tough-0.22.0/src/lib.rs:117-247` and `sigstore-trust-root-0.7.0/src/tuf.rs:349-372`. Direct upstream code is reproducible. |
| Req 2 | HTTP client consults Windows certificate store | `ureq::Agent::config_builder().tls_config(TlsConfig::builder().root_certs(RootCerts::PlatformVerifier).build()).build().new_agent()` confirmed at `ureq-3.3.0/src/lib.rs:256-273` and `ureq-3.3.0/src/tls/mod.rs:298-303`. Feature `platform-verifier` already present in `nono-cli/Cargo.toml:73`. |
| Req 3 | TUF verification correctness preserved via tough | `tough::lib::load_root` step 5.2 (`tough-0.22.0/src/lib.rs:699-707`) and step 5.3 chain walk (lines 729-803) are inside the `tough` crate and run unchanged via `RepositoryLoader::load()`. nono only provides bytes; signature math stays in tough. |
| Req 4 | Byte-identical `trusted_root.json` cache | `TrustedRoot` derives `Serialize + Deserialize` (`sigstore-trust-root-0.7.0/src/trusted_root.rs:18`). After chain walk, `repo.read_target(&TargetName::new(TRUSTED_ROOT_TARGET)?).await?.into_vec().await?` gives raw bytes. Parse via `TrustedRoot::from_json(&utf8_str)`. Re-serialize via `serde_json::to_string_pretty(&trusted_root)` matches existing `setup.rs:857`. |
| Req 5 | ≥ 4 hermetic tests | `tough::Transport` trait at `tough-0.22.0/src/transport.rs:46-49` is `async-trait`-based with `Debug + DynClone + Send + Sync` bounds. `StaticMapTransport` implementing `fetch(url) -> Result<TransportStream, TransportError>` covers all four test scenarios. |
| Req 6 | HUMAN-UAT scenario | Out-of-scope-for-research; deliverable is a markdown file in the phase dir. |
</phase_requirements>

## Project Constraints (from CLAUDE.md)

- **`#![deny(clippy::unwrap_used)]`** — no `.unwrap()` / `.expect()` in production code (test code OK with `#[allow]`).
- **Cross-target clippy MUST/NEVER** — every commit touching cfg-gated Unix code (or platform-impacting deps) must run clippy on `x86_64-unknown-linux-gnu` AND `x86_64-apple-darwin` from dev host. Phase 50 D-50-13 escalates this to hard-pass (no PARTIAL deferral) because the addition of `tough` as a direct dep + the introduction of `trust_refresh` is a workspace-affecting change.
- **Fail-secure on any error** — never silently degrade.
- **Path-handling rules** — only the cache_path / datastore path matter here; both are derived from `crate::config::nono_home_dir()` which already canonicalizes via `dirs::home_dir()` + `NONO_TEST_HOME` validation.
- **No new transitive sigstore deps** — `tough 0.22.0` is already in the lockfile via `sigstore-trust-root 0.7.0`. Promoting it to direct dep does NOT add a new top-level package; verify via `cargo tree -p nono-cli` after the Cargo.toml edit.
- **DCO sign-off** required on every commit.

## Summary

Phase 50 replaces ONE upstream call (`nono::trust::TrustedRoot::production()` at `setup.rs:849`) with a new nono-local TUF chain-walk function (`trust_refresh::refresh_production_trusted_root()`). The new function reuses upstream `tough::RepositoryLoader` for spec-compliant TUF verification but supplies its own HTTP transport (`UreqTransport(ureq::Agent)`) that consults the OS certificate store via the `platform-verifier` feature — bypassing the `webpki-roots`-only TLS trust path of `reqwest 0.12.28` that fails on corporate TLS-inspecting networks.

The implementation is a direct port of `sigstore-trust-root-0.7.0/src/tuf.rs::TufClient::load_repository` + `read_target_from_repo` (lines 349-407) with TWO substitutions: (1) `tough::HttpTransport::default()` → `UreqTransport(ureq_agent)`, (2) the directories crate's cache dir → `nono_home_dir().join(".nono/trust-root/tuf-cache")`. The output value (`Vec<u8>` → `TrustedRoot` via `from_json`) and serialization (`serde_json::to_string_pretty`) are byte-identical to what the existing call produces.

**CRITICAL FINDING:** `tough::Transport::fetch` is **`async`** (verified at `tough-0.22.0/src/transport.rs:46-49`), `tough::RepositoryLoader::load` is **`async`** (line 206), and `tough::Repository::read_target` is **`async`** (line 458). The CONTEXT.md statement that "`tough` + `ureq` are sync, no tokio runtime needed" (D-50 implementation insight) is **INCORRECT**: the `tokio::runtime::Builder::new_current_thread()` block at `setup.rs:844-848` **MUST BE PRESERVED**. The only change is that the new module's `refresh_production_trusted_root` may either (a) accept an `async fn` signature and be called inside the existing `rt.block_on(...)`, or (b) hide the block_on inside a `pub fn` wrapper that builds its own one-shot runtime. The Phase 50 planner must pick one shape; either is fine, but the runtime cannot be eliminated entirely. **This contradicts CONTEXT.md sentence in `<code_context>` section** — flag for planner.

**Primary recommendation:** Follow the verbatim shape of sigstore-trust-root-0.7.0's `TufClient::load_repository` (a single ~30-line async function) plus a 15-line `UreqTransport` implementing `tough::Transport` via `tokio::task::spawn_blocking` (because `ureq::Agent` is sync). Recreate the `read_target → into_vec` flow for the `"trusted_root.json"` target. Total new code: ~150 lines of production + ~200 lines of tests.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| TUF chain walk (signature verification, version walk) | tough crate | — | Spec-critical math stays in audited upstream; D-50-04 lock |
| HTTP transport (TLS handshake, cert validation) | ureq + rustls-platform-verifier | OS root store (Crypt32/Security/openssl) | Honors enterprise CAs; D-50-11 single cross-platform path |
| Bytes → `TrustedRoot` value parsing | sigstore-trust-root | — | `TrustedRoot::from_json` is the canonical parser; reused for byte-identity |
| Cache file write (serde_json::to_string_pretty + std::fs::write) | nono-cli setup module | — | Preserves existing `setup.rs:857-860` shape; cache contract unchanged |
| TUF datastore (latest_known_time.json, intermediate roots) | tough internal | nono-cli (provides path) | tough manages datastore contents; nono provides the directory |
| Phase index header `[X/N]` + cleanup ceremony | nono-cli setup module | — | Mirrors Phase 49 `from_file_step` shape (D-49-B2) |

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `tough` | 0.22.0 | TUF spec-compliant repository loader; signature verification math | Already in lockfile; used by sigstore-trust-root 0.7.0; audited by AWS |
| `ureq` | 3.x (3.3.0 in lockfile) | Sync HTTP client with rustls + platform-verifier feature | Already in `nono-cli/Cargo.toml:73` with `platform-verifier` feature enabled |
| `sigstore-trust-root` | 0.7.0 | Source for `PRODUCTION_TUF_ROOT`, `DEFAULT_TUF_URL`, `TRUSTED_ROOT_TARGET` consts | Already a transitive dep via `sigstore-verify`; provides synced anchor |
| `sigstore-verify` | 0.7.0 (re-exports `TrustedRoot`) | Return type for `refresh_production_trusted_root` | Already re-exported as `nono::trust::TrustedRoot` |
| `url` | 2.5.8 | URL parsing for metadata/targets base URLs | Already in `nono-cli/Cargo.toml:84` |
| `tokio` | 1.x | One-shot current-thread runtime to drive `tough`'s async API | Already in `nono-cli/Cargo.toml:71` |
| `async-trait` | 0.1.x | Implementing `tough::Transport`'s `#[async_trait]` macro | Transitively in lockfile; required for the trait impl |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `futures` | (transitive) | Stream → Vec collection via `IntoVec` trait | Already pulled by tough |
| `bytes` | 1.x | `Bytes` chunk type for transport stream | Already pulled by tough/tokio-util |
| `tokio-util` | 0.7.x | `ReaderStream` if implementing streaming transport | Already in lockfile; **not needed** for canned in-memory test transport |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `ureq 3 + platform-verifier` | `reqwest 0.13.3` with `rustls-platform-verifier 0.7.0` | reqwest 0.13.3 IS in lockfile via other paths; would add tokio overhead but reqwest is async-native. ureq chosen because (a) already declared in nono-cli Cargo.toml, (b) sync API simpler for a single one-shot fetch, (c) smaller dep tree |
| `tough::RepositoryLoader` | `sigstore_trust_root::tuf::TufClient` | TufClient is `struct TufClient` (private — see `sigstore-trust-root-0.7.0/src/tuf.rs:279`); not re-exported in `lib.rs:80-104`. Cannot use it directly. |
| Direct `tough` usage | Forking sigstore-trust-root to inject a custom transport | Fork burden; SPEC out-of-scope (Deferred — Surface (b)) |

**Verified versions (npm/cargo registry):**

```bash
# Verify tough is at expected version in lockfile
grep -A 1 '^name = "tough"' Cargo.lock
# Expected output:
#   name = "tough"
#   version = "0.22.0"

# Verify ureq + platform-verifier feature
grep 'ureq.*platform-verifier' crates/nono-cli/Cargo.toml
# Expected: ureq = { version = "3", features = ["platform-verifier"] }

# Verify sigstore-trust-root version
grep -A 1 '^name = "sigstore-trust-root"' Cargo.lock
# Expected: version = "0.7.0"
```

**Installation:**

```bash
# In crates/nono-cli/Cargo.toml [dependencies]:
tough = "0.22"
# That's the ONLY dep add. async-trait, url, tokio, ureq, sigstore-verify already declared.
# Verify no new transitive top-level deps after edit:
cargo tree -p nono-cli --depth 1 | sort > /tmp/tree-before
# (edit Cargo.toml)
cargo tree -p nono-cli --depth 1 | sort > /tmp/tree-after
diff /tmp/tree-before /tmp/tree-after
# Expected: only `+tough v0.22.0` line; no other additions.
```

## Architecture Patterns

### System Architecture Diagram

```
[setup.rs::refresh_trust_root_step]
   │
   │  (1) Print "[X/N] Refreshing Sigstore trusted root..."
   │  (2) Create cache dir: <nono_home>/.nono/trust-root/
   │  (3) Build one-shot tokio runtime (PRESERVED — tough is async)
   │      │
   │      └─→ rt.block_on(trust_refresh::refresh_production_trusted_root())
   │            │
   │            ├─→ Build ureq::Agent with platform-verifier
   │            │     │
   │            │     └─→ OS root store (Crypt32 / Security / OpenSSL)
   │            │
   │            ├─→ Build UreqTransport(agent) impl tough::Transport
   │            │     │   fetch(url) wraps tokio::task::spawn_blocking { agent.get(url).call() }
   │            │     │
   │            │     └─→ Returns TransportStream of bytes
   │            │
   │            ├─→ tough::RepositoryLoader::new(PRODUCTION_TUF_ROOT, metadata_url, targets_url)
   │            │     .transport(UreqTransport(agent))
   │            │     .datastore(<nono_home>/.nono/trust-root/tuf-cache/)
   │            │     .load().await
   │            │     │   Inside tough:
   │            │     │     5.2: verify embedded v14 anchor against itself
   │            │     │     5.3: fetch N+1.root.json loop until 404; verify chain at every step
   │            │     │     timestamp.json → snapshot.json → targets.json
   │            │     │
   │            │     └─→ Repository value
   │            │
   │            ├─→ repo.read_target(&TargetName::new("trusted_root.json")?)
   │            │     .await?
   │            │     .ok_or(NotFound)?
   │            │     .into_vec().await?
   │            │     │
   │            │     └─→ Vec<u8> of trusted_root.json bytes
   │            │
   │            └─→ TrustedRoot::from_json(utf8_str)? → TrustedRoot
   │
   │  (4) serde_json::to_string_pretty(&trusted_root) → JSON string
   │  (5) std::fs::write(cache_path, json) → byte-identical cache file
   │  (6) Print "  * Sigstore trusted root cached at ..."
```

### Recommended Project Structure

```
crates/nono-cli/src/
├── main.rs                  # +1 line: `mod trust_refresh;` (alphabetical insert near line ~88)
├── setup.rs                 # MODIFY refresh_trust_root_step() body (lines 828-868)
└── trust_refresh.rs         # NEW FILE: ~150 lines production + ~200 lines tests
```

### Pattern 1: `tough::Transport` impl for ureq::Agent (the bridge)

**What:** Wraps a sync `ureq::Agent` in an async `tough::Transport` impl using `tokio::task::spawn_blocking` to bridge the sync→async boundary.

**When to use:** Required because `tough::Transport::fetch` returns `async fn` but `ureq::Agent::get(...).call()` is sync.

**Example** (target shape — copy this verbatim into the new module):

```rust
// Source: tough-0.22.0/src/transport.rs:46-49 (trait def)
// Source: tough-0.22.0/src/http.rs:142-150 (HttpTransport reference impl)

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream;
use std::sync::Arc;
use tough::{Transport, TransportError, TransportErrorKind, TransportStream};
use ureq::Agent;
use url::Url;

#[derive(Debug, Clone)]
struct UreqTransport {
    agent: Agent,
}

#[async_trait]
impl Transport for UreqTransport {
    async fn fetch(&self, url: Url) -> Result<TransportStream, TransportError> {
        let agent = self.agent.clone();
        let url_str = url.to_string();
        let result = tokio::task::spawn_blocking(move || {
            agent
                .get(&url_str)
                .call()
                .and_then(|mut resp| {
                    resp.body_mut().read_to_vec().map_err(Into::into)
                })
        })
        .await
        .map_err(|e| TransportError::new_with_cause(
            TransportErrorKind::Other,
            url.clone(),
            e,
        ))?;

        match result {
            Ok(bytes) => {
                // Single chunk — emit as one-element stream
                let stream = stream::iter(std::iter::once(Ok(Bytes::from(bytes))));
                Ok(Box::pin(stream))
            }
            Err(ureq::Error::StatusCode(code)) if code == 404 || code == 403 || code == 410 => {
                // tough treats 403/404/410 as FileNotFound (see tough-0.22.0/src/http.rs:126-130)
                Err(TransportError::new(TransportErrorKind::FileNotFound, url))
            }
            Err(e) => Err(TransportError::new_with_cause(
                TransportErrorKind::Other,
                url,
                e,
            )),
        }
    }
}
```

Notes for planner:
- The `read_to_vec` API on `ureq::Body` requires confirmation against ureq 3.3.0 docs — planner verifies via `cargo doc -p ureq --open` or Context7 lookup. If absent, use `resp.body_mut().into_reader().read_to_end(&mut buf)` instead.
- Status code mapping mirrors `tough::http::ErrorClass::FileNotFound` semantics — tough's contract is that 403/404/410 indicate "file does not exist" so the chain walk knows when to stop. Other 4xx/5xx are `Other` errors.

### Pattern 2: `ureq::Agent` with platform-verifier

**What:** Constructs the HTTP client that honors the OS root cert store.

**Example** (verbatim from `ureq-3.3.0/src/lib.rs:256-273`):

```rust
// Source: ureq-3.3.0/src/lib.rs:256-273
use ureq::Agent;
use ureq::tls::{TlsConfig, RootCerts};
use std::time::Duration;

fn build_corp_friendly_agent() -> Agent {
    Agent::config_builder()
        .tls_config(
            TlsConfig::builder()
                .root_certs(RootCerts::PlatformVerifier)  // ← Windows: Crypt32, macOS: Security, Linux: ca-certificates
                .build()
        )
        .timeout_global(Some(Duration::from_secs(30)))    // matches tough HttpTransport default
        .timeout_connect(Some(Duration::from_secs(10)))
        .build()
        .new_agent()
}
```

Notes:
- `RootCerts::PlatformVerifier` is the discriminator that triggers the `rustls-platform-verifier` path. The `platform-verifier` Cargo feature gates the entire `rustls-platform-verifier` dep — confirmed at `ureq-3.3.0/Cargo.toml:100`.
- Timeouts are planner's discretion (CONTEXT.md). Suggested values match `tough::HttpTransport`'s defaults (`tough-0.22.0/src/http.rs:55-64`): 30s total, 10s connect.
- `Agent` derives `Clone` — cloning is cheap (Arc internals, see `ureq-3.3.0/src/agent.rs:89-99`); use a fresh clone per `UreqTransport.fetch` call inside `spawn_blocking`.

### Pattern 3: `tough::RepositoryLoader` invocation

**What:** Drives the TUF chain walk + retrieves the `trusted_root.json` target bytes.

**Example** (direct port from `sigstore-trust-root-0.7.0/src/tuf.rs:349-407`):

```rust
// Source: sigstore-trust-root-0.7.0/src/tuf.rs:349-407 (load_repository + read_target_from_repo)
// Source: tough-0.22.0/src/lib.rs:117-247 (RepositoryLoader API)

use sigstore_trust_root::{PRODUCTION_TUF_ROOT, DEFAULT_TUF_URL, TRUSTED_ROOT_TARGET};
use sigstore_verify::trust_root::TrustedRoot;
use tough::{RepositoryLoader, TargetName, IntoVec};
use url::Url;
use std::path::PathBuf;
use crate::error::{NonoError, Result};

pub async fn refresh_production_trusted_root() -> Result<TrustedRoot> {
    // 1. URL setup (mirrors sigstore-trust-root tuf.rs:350-354)
    let base_url = Url::parse(DEFAULT_TUF_URL)
        .map_err(|e| NonoError::Setup(format!("invalid Sigstore TUF URL: {e}")))?;
    let metadata_url = base_url.clone();
    let targets_url = base_url
        .join("targets/")
        .map_err(|e| NonoError::Setup(format!("invalid Sigstore targets URL: {e}")))?;

    // 2. Datastore dir (nono-specific path; tough manages contents)
    let datastore_dir = crate::config::nono_home_dir()
        .map_err(|e| NonoError::Setup(format!("home dir: {e}")))?
        .join(".nono")
        .join("trust-root")
        .join("tuf-cache");
    tokio::fs::create_dir_all(&datastore_dir).await.map_err(|e| {
        NonoError::Setup(format!("create tuf-cache dir {}: {e}", datastore_dir.display()))
    })?;

    // 3. Build agent + transport
    let agent = build_corp_friendly_agent();
    let transport = UreqTransport { agent };

    // 4. Load repository (drives the chain walk + signature verification)
    let repo = RepositoryLoader::new(&PRODUCTION_TUF_ROOT, metadata_url, targets_url)
        .transport(transport)
        .datastore(datastore_dir.clone())
        .load()
        .await
        .map_err(|e| {
            // Best-effort cleanup: remove tuf-cache on failure to avoid partial state
            // (D-49-B2 pattern; planner decides whether to remove the dir or just contents)
            let _ = std::fs::remove_dir_all(&datastore_dir);
            NonoError::Setup(format!("Sigstore TUF refresh failed: {e}"))
        })?;

    // 5. Fetch trusted_root.json target
    let target_name = TargetName::new(TRUSTED_ROOT_TARGET)
        .map_err(|e| NonoError::Setup(format!("invalid target name: {e}")))?;
    let stream = repo
        .read_target(&target_name)
        .await
        .map_err(|e| NonoError::Setup(format!("read trusted_root target: {e}")))?
        .ok_or_else(|| NonoError::Setup(format!("Sigstore target not found: {TRUSTED_ROOT_TARGET}")))?;

    let bytes = stream
        .into_vec()
        .await
        .map_err(|e| NonoError::Setup(format!("collect trusted_root bytes: {e}")))?;

    // 6. Parse to TrustedRoot value
    let json = std::str::from_utf8(&bytes)
        .map_err(|e| NonoError::Setup(format!("trusted_root.json is not UTF-8: {e}")))?;
    TrustedRoot::from_json(json)
        .map_err(|e| NonoError::Setup(format!("parse trusted_root.json: {e}")))
}
```

Key API confirmations (all from `tough-0.22.0/src/lib.rs`):
- `RepositoryLoader::new(root: &impl AsRef<[u8]>, metadata_base_url: Url, targets_base_url: Url)` (line 193)
- `.transport(impl Transport + Send + Sync + 'static)` (line 212)
- `.datastore(impl Into<PathBuf>)` (line 232)
- `.load() -> Result<Repository>` is `async` (line 206)
- `Repository::read_target(&TargetName) -> Result<Option<impl Stream<...> + IntoVec<error::Error>>>` (line 458)
- `IntoVec::into_vec()` is `async` and collects the stream into `Vec<u8>` (`tough-0.22.0/src/transport.rs:21-36`)

### Pattern 4: Call-site change in `setup.rs::refresh_trust_root_step`

**Current** (`setup.rs:828-868`):

```rust
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

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| NonoError::Setup(format!("tokio runtime: {e}")))?;
    let trusted_root = rt
        .block_on(nono::trust::TrustedRoot::production())
        .map_err(|e| { ... })?;

    let json = serde_json::to_string_pretty(&trusted_root)
        .map_err(|e| NonoError::Setup(format!("serialize trusted root: {e}")))?;
    let cache_path = cache_dir.join("trusted_root.json");
    std::fs::write(&cache_path, &json).map_err(NonoError::Io)?;

    println!("  * Sigstore trusted root cached at {}", cache_path.display());
    println!();
    Ok(())
}
```

**Target** (minimum change — preserves the runtime, header, write, success-print):

```rust
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

    println!("  * Sigstore trusted root cached at {}", cache_path.display());
    println!();
    Ok(())
}
```

Diff is ~3 lines: the `rt.block_on` arg changes from `nono::trust::TrustedRoot::production()` to `crate::trust_refresh::refresh_production_trusted_root()`. The error wrap text is identical.

**CONTEXT.md correction:** The statement at CONTEXT.md `<code_context>` Integration Points section — "Phase 50 ELIMINATES the only async call in `refresh_trust_root_step`, which simplifies the function meaningfully" — is **wrong**. `tough::RepositoryLoader::load`, `Repository::read_target`, and `IntoVec::into_vec` are all async; the runtime stays. Planner should NOT delete the `tokio::runtime::Builder` block. Adjust commit-message and plan task wording accordingly.

### Anti-Patterns to Avoid

- **Implementing `Transport::fetch` as `fn` (non-async):** The trait is `#[async_trait]`-decorated. Sync impl won't compile. Use `tokio::task::spawn_blocking` to call sync `ureq` from inside the async body.
- **Constructing a fresh `ureq::Agent` per `fetch` call:** Wastes connection-pool reuse. Store the `Agent` in `UreqTransport.agent` and `.clone()` (cheap — Arc-based).
- **Building TLS config via low-level rustls APIs:** ureq's `TlsConfig::builder().root_certs(RootCerts::PlatformVerifier)` does the right thing. Hand-rolling rustls is forbidden by spec (and footgun for cert verification edge cases).
- **Treating ureq `400`/`500` HTTP status codes as success bytes:** ureq v3's default IS `http_status_as_error: true` (returns `Err(ureq::Error::StatusCode(...))` for 4xx/5xx). Map 403/404/410 to `FileNotFound` so tough's chain walk terminates correctly; map others to `TransportErrorKind::Other`.
- **Forgetting to create the datastore directory:** `tough::RepositoryLoader::load` requires the datastore dir to exist before `.load()` is called (`tough-0.22.0/src/lib.rs:228-231`). Use `tokio::fs::create_dir_all` (async, since we're inside an async fn) BEFORE building the loader. Failure to do this surfaces as an obscure `DatastoreError`.
- **Mixing sync `std::fs` and async `tokio::fs` carelessly:** Inside the async function, prefer `tokio::fs::create_dir_all` for dir creation (matches upstream pattern at `sigstore-trust-root-0.7.0/src/tuf.rs:362`). Outside (in `setup.rs::refresh_trust_root_step`, before block_on), sync `std::fs` is correct.
- **Forgetting to clean tuf-cache dir on failure:** D-49-B2 cleanup pattern. On any `Err` after the dir exists, best-effort `std::fs::remove_dir_all(&datastore_dir)`. Leaving partial state breaks the next refresh attempt.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| TUF signature verification | `tough::schema::Signed<Root>::verify_role` loop | `tough::RepositoryLoader::load()` | SPEC Req 3 explicit forbid; signature math is security-critical and audited upstream |
| TLS handshake / cert validation | rustls `ClientConfig::builder` direct API | `ureq::tls::TlsConfig::builder().root_certs(RootCerts::PlatformVerifier)` | rustls config minefield; platform-verifier integration is exactly the value-add we need |
| Embedded TUF v14 root JSON | `include_bytes!("our-tuf-root.json")` | `sigstore_trust_root::PRODUCTION_TUF_ROOT` | D-50-06 lock; staleness class identical to Phase 49 if we re-ship; auto-syncs with sigstore-trust-root bumps |
| HTTP retry/backoff | Manual retry loop | None — single attempt is fine | tough's own `HttpTransport` has retries baked in, but for a one-shot setup command, a single attempt with a clear failure message is preferable; user re-runs setup. Adding retries multiplies test surface. |
| Localhost test HTTP server | tiny_http / axum / wiremock fixture | `StaticMapTransport(HashMap<String, Vec<u8>>)` impl `tough::Transport` | D-50-08 lock; no port flake, no Defender interference, faster |

**Key insight:** The entire phase reduces to "compose two upstream APIs cleanly" — there is essentially zero security-critical novel code. The only novel surface is the `Transport` impl bridging sync↔async, which is a 30-line glue function with one test (round-trip via `StaticMapTransport`).

## Runtime State Inventory

> N/A — Phase 50 is a code change with no rename, no migration, no string-substitution. The only on-disk state introduced is a new directory (`<nono_home>/.nono/trust-root/tuf-cache/`) which tough creates lazily on first run.

**Stored data:** None (the new directory contains transient TUF metadata that tough manages internally; no semantic data).

**Live service config:** None.

**OS-registered state:** None.

**Secrets/env vars:** None new. `NONO_TEST_HOME` is honored transitively via `nono_home_dir()` — already covered by existing test infrastructure.

**Build artifacts:** A direct `tough` dep promotion in `nono-cli/Cargo.toml` may change the resolved feature set for `tough` (if the existing transitive consumer enabled different features). Verify via `cargo tree -p nono-cli -e features | grep tough` before and after. Expected: no feature diff because both consumers (sigstore-trust-root + new direct dep) likely want default features.

## Common Pitfalls

### Pitfall 1: Mis-reading `tough::Transport::fetch` as sync

**What goes wrong:** Implementer reads CONTEXT.md "tough + ureq are sync" line, writes a sync `fn fetch(...)`, gets compile errors complaining about missing `Future` impl on return type.

**Why it happens:** CONTEXT.md authoring error — `ureq` is sync, but `tough::Transport::fetch` is `async` via `#[async_trait]`. ureq is the sync part; the trait bridge needs `tokio::task::spawn_blocking`.

**How to avoid:** Cite `tough-0.22.0/src/transport.rs:46-49` directly in the planner's task description. Copy the `Pattern 1` example verbatim — it has the correct `#[async_trait]` decoration.

**Warning signs:** Compile error containing `expected fn(...) -> Pin<Box<dyn Future<...>>>` or "the trait `Transport` is not implemented for `UreqTransport`".

### Pitfall 2: Datastore directory missing → cryptic `DatastoreError`

**What goes wrong:** Skipping the `tokio::fs::create_dir_all(&datastore_dir)` step before `RepositoryLoader.datastore(...)` causes `load()` to fail with a non-obvious error chain involving "datastore path does not exist" buried under "TUF repository load failed".

**Why it happens:** Tough's contract (`tough-0.22.0/src/lib.rs:228-231` docstring) explicitly requires the dir to exist. Upstream's own sigstore-trust-root code does this at `tuf.rs:362`.

**How to avoid:** Always pair `.datastore(path)` with a `create_dir_all(&path)` call immediately before. Add a unit test that points the loader at a non-existent datastore and asserts the error message contains "tuf-cache" or "datastore" so future regressions surface cleanly.

**Warning signs:** Error message `TUF repository load failed: failed to create datastore: ...` or similar in HUMAN-UAT output.

### Pitfall 3: ureq v3 API drift on `Body::read_to_vec`

**What goes wrong:** Implementer copies the Pattern 1 example, calls `resp.body_mut().read_to_vec()`, finds the method does not exist in ureq 3.3.0 (or has a different signature).

**Why it happens:** ureq v3 is post-API-stabilization but planner is working from secondhand examples. The body-reading API may be `body_mut().into_reader().read_to_end(&mut buf)` or `body_mut().read_to_string()` or use a streaming reader differently.

**How to avoid:** Planner runs `cargo doc -p ureq --open` (or `npx ctx7 docs ureq Body` if Context7 is available) before writing the task action. Confirm the exact method name on `ureq::Body`. The fallback is universally available: `let mut buf = Vec::new(); resp.body_mut().into_reader().read_to_end(&mut buf)?;`.

**Warning signs:** `method 'read_to_vec' not found on Body` compile error.

### Pitfall 4: 403/404/410 status codes mis-classified

**What goes wrong:** Transport returns `TransportErrorKind::Other` for HTTP 404, causing tough's chain walk to abort with an error instead of cleanly terminating ("we've reached the latest root").

**Why it happens:** TUF spec 5.3.3 says "if N+1.root.json is not available, go to step 5.3.10" — i.e., a 404 on the next root version is the SIGNAL to stop walking. Tough relies on `TransportErrorKind::FileNotFound` for this; see the `Err(_) => break` branch at `tough-0.22.0/src/lib.rs:759-763`.

**How to avoid:** Explicitly match on `ureq::Error::StatusCode(404 | 403 | 410)` and return `TransportError::new(TransportErrorKind::FileNotFound, url)`. Confirmed by upstream tough HTTP transport behavior: `tough-0.22.0/src/http.rs:126-130` ("This transport returns `FileNotFound` for 403, 404, 410").

**Warning signs:** Live (or HUMAN-UAT) refresh succeeds bootstrap but fails with "Failed to fetch 16.root.json: Transport 'other' error" when there is no v16 yet. The chain walk should stop at the last existing version.

### Pitfall 5: Snapshot test compares against wrong baseline

**What goes wrong:** Test compares chain-walk output bytes against `SIGSTORE_PRODUCTION_TRUSTED_ROOT` (the embedded fallback) — but those bytes are an EMBEDDED snapshot, not the live CDN output. If the test transport serves a different version of `trusted_root.json` as the "target", the snapshot match will fail spuriously.

**Why it happens:** SPEC Req 4 says "byte-identical to `TrustedRoot::production()` output against the same hermetic TUF repo". The test fixture's `trusted_root.json` content IS the baseline — whatever bytes the `StaticMapTransport` returns for that target ARE what should appear in the cache. The assertion is `serde_json::to_string_pretty(&parsed) == serde_json::to_string_pretty(&parsed_from_cache)`, not "equals embedded const".

**How to avoid:** The snapshot test should:
1. Put a known JSON blob (e.g., `SIGSTORE_PRODUCTION_TRUSTED_ROOT` bytes) into the test transport at key `"targets/<sha256_hex>.trusted_root.json"` (or `"targets/trusted_root.json"` depending on consistent_snapshots setting).
2. Run the chain walk.
3. Assert the OUTPUT bytes equal `serde_json::to_string_pretty(&TrustedRoot::from_json(SIGSTORE_PRODUCTION_TRUSTED_ROOT_str).unwrap()).unwrap()`.

This avoids the round-trip equality trap where parse→reserialize may not equal original bytes (key order, whitespace).

**Warning signs:** Snapshot test fails with diff like `expected 12345 bytes, got 12340 bytes` despite the JSON being semantically equal.

## Code Examples

Verified patterns from official sources (copy into PLAN.md task `action` fields):

### Example A: Build the ureq Agent (Pattern 2, complete)

```rust
// Source: ureq-3.3.0/src/lib.rs:256-273
use std::time::Duration;
use ureq::Agent;
use ureq::tls::{RootCerts, TlsConfig};

fn build_corp_friendly_agent() -> Agent {
    Agent::config_builder()
        .tls_config(
            TlsConfig::builder()
                .root_certs(RootCerts::PlatformVerifier)
                .build()
        )
        .timeout_global(Some(Duration::from_secs(30)))
        .timeout_connect(Some(Duration::from_secs(10)))
        .build()
        .new_agent()
}
```

### Example B: StaticMapTransport for hermetic tests (D-50-08)

```rust
// Pattern derived from tough::Transport trait at tough-0.22.0/src/transport.rs:46-49
// and tough's own test patterns at tough-0.22.0/tests/transport.rs

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream;
use std::collections::HashMap;
use std::sync::Arc;
use tough::{Transport, TransportError, TransportErrorKind, TransportStream};
use url::Url;

#[derive(Debug, Clone)]
struct StaticMapTransport {
    files: Arc<HashMap<String, Vec<u8>>>,
}

impl StaticMapTransport {
    fn new(files: HashMap<String, Vec<u8>>) -> Self {
        Self { files: Arc::new(files) }
    }
}

#[async_trait]
impl Transport for StaticMapTransport {
    async fn fetch(&self, url: Url) -> Result<TransportStream, TransportError> {
        // Match by URL path (strip leading slash for HashMap key compatibility)
        let key = url.path().trim_start_matches('/').to_string();
        match self.files.get(&key) {
            Some(bytes) => {
                let s = stream::iter(std::iter::once(Ok(Bytes::from(bytes.clone()))));
                Ok(Box::pin(s))
            }
            None => Err(TransportError::new(TransportErrorKind::FileNotFound, url)),
        }
    }
}
```

### Example C: Building a hermetic test fixture map

```rust
// Test fixture layout:
//   The TUF chain-walk fetches (in order):
//     - {metadata_url}/2.root.json (we use a version > embedded root version)
//     - {metadata_url}/3.root.json → returns FileNotFound (stops chain walk)
//     - {metadata_url}/timestamp.json
//     - {metadata_url}/snapshot.json
//     - {metadata_url}/targets.json
//     - {targets_url}/trusted_root.json (or {targets_url}/<sha>.trusted_root.json for consistent_snapshots)
//
// For Phase 50 tests, generate a minimal valid TUF repo using tuftool (Bottlerocket's CLI)
// or hand-craft using tough::schema primitives. Recommended approach: check in a
// pre-generated fixture directory at crates/nono-cli/tests/fixtures/tuf-repo-{v15,v15-bad-sig,malformed}/
// containing {1.root.json, 2.root.json, timestamp.json, snapshot.json, targets.json, trusted_root.json},
// and load it into the StaticMapTransport at test setup.

fn load_fixture(name: &str) -> HashMap<String, Vec<u8>> {
    let fixture_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    let mut map = HashMap::new();
    for entry in std::fs::read_dir(&fixture_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        let bytes = std::fs::read(entry.path()).unwrap();
        map.insert(name, bytes);
    }
    map
}
```

**Fixture generation guidance (planner's discretion):**

The Phase 50 planner has two options for generating the test fixtures:

1. **Pre-generated checked-in fixtures (recommended):**
   - Use `tuftool` (https://github.com/awslabs/tough/tree/develop/tuftool) one-time to generate a tiny test repo whose root.json is signed by a known test key.
   - Commit the generated JSON files to `crates/nono-cli/tests/fixtures/tuf-repo-happy/`.
   - For the bad-signature variant, copy the happy-path repo and flip one byte in `2.root.json`'s signature field.
   - For malformed-JSON, copy and truncate `2.root.json`.
   - **Embedded anchor for tests:** the test's "embedded v1 root" is the `1.root.json` from this checked-in fixture (NOT the production `PRODUCTION_TUF_ROOT`). The production anchor only appears in the happy-path against the LIVE CDN (which we don't test against in Phase 50).
   - **Trusted target:** put any valid JSON (e.g., `SIGSTORE_PRODUCTION_TRUSTED_ROOT` bytes if test repo's signing keys match it, or any small placeholder if not) at the `trusted_root.json` target path.

2. **Programmatic generation at test-time using `tough::editor::RepositoryEditor`:**
   - `tough-0.22.0/src/editor` exposes a builder for crafting signed TUF repositories.
   - Generates a fresh keypair per test, signs metadata, returns a HashMap of bytes.
   - More flexible but adds runtime cost and ties tests to tough's editor API stability.

Planner picks one approach in the PLAN; option 1 is simpler.

### Example D: Cargo.toml dep promotion

```toml
# In crates/nono-cli/Cargo.toml under [dependencies]:
# (alphabetically near `tokio = { version = "1", ... }` line 71-73 vicinity)

# Phase 50: promoted from transitive (via sigstore-trust-root 0.7.0) to direct
# dep so we can call tough::RepositoryLoader directly with our own Transport impl.
# Version pinned to lockfile entry to avoid pulling a second copy.
tough = "0.22"

# Transitive Transport-trait deps (already in lockfile via tough; declared
# here only if compile errors say they're needed at the call site):
# - async-trait = "0.1"  (for #[async_trait] on UreqTransport)
# - bytes = "1"          (for Bytes type)
# - futures = "0.3"      (for stream::iter helper)
```

Note: `async-trait`, `bytes`, `futures` are transitively available, but Rust's orphan rules don't apply here (we're not implementing foreign traits for foreign types). However, the `#[async_trait]` macro is from the crate, so adding `async-trait = "0.1"` as a direct dep is required if the compiler complains about missing the crate name. Verify after first `cargo build` and add only if needed (CLAUDE.md "lazy use of dead code" — don't add deps speculatively).

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `webpki-roots` bundled CAs (reqwest 0.12.28 default) | `rustls-platform-verifier` (delegates to OS root store) | rustls-platform-verifier 0.6+ widely-adopted as of 2025 | Enterprise CAs deployed via GPO/MDM are honored without rebuild |
| TUF chain walk inside upstream sigstore-rs | Per-consumer TUF walk with custom transport | Pattern emerged in 2024 (sigstore-rs added `from_tuf(config)` builder) | Consumers can swap HTTP client without forking sigstore-rs |
| reqwest async HTTP for tough | ureq sync HTTP via spawn_blocking | Cross-pattern; both work | ureq simpler for one-shot fetches; reqwest better for high-concurrency |
| Localhost HTTP server in TUF tests | In-memory `Transport` impl | Standard since tough 0.18+ | No port flake on CI; faster; more deterministic |

**Deprecated/outdated:**
- "Sigstore TUF requires reqwest" — false. tough's `Transport` trait is the seam; reqwest is one of many possible implementations.
- "ureq doesn't support OS root store" — false as of ureq 3.x with the `platform-verifier` feature flag.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | ureq 3.3.0 exposes `Body::read_to_vec()` | Pattern 1 | Implementer uses `into_reader().read_to_end()` fallback (universally available); fix is one-line |
| A2 | `tough::HttpTransport`'s 403/404/410 → `FileNotFound` mapping is the right behavioral contract for `UreqTransport` | Pitfall 4 + Pattern 1 | If wrong, TUF chain walk may not terminate cleanly; HUMAN-UAT would catch this. Mitigation: confirm via tough integration test snapshots or unit-test the boundary |
| A3 | `serde_json::to_string_pretty(&trusted_root)` produces deterministic byte output across compile runs given the same input | Pattern 3 + Req 4 | If serde_json key ordering or float-formatting differs across versions, the snapshot test would flake. Mitigation: pin serde_json minor in lockfile (already done) and assert `from_json → to_string_pretty` is idempotent in a separate test |
| A4 | The CONTEXT.md statement "tough + ureq are sync, no tokio runtime needed" is incorrect | Summary + Pattern 4 | This research's main correction; verified by reading `tough/src/transport.rs:46-49` and `tough/src/lib.rs:206`. Planner MUST preserve the tokio runtime in `refresh_trust_root_step` |
| A5 | Direct `tough = "0.22"` Cargo.toml add does NOT pull a second copy of tough into lockfile | Standard Stack | Verified by lockfile-already-has-tough-0.22.0 reading; `cargo tree` diff before/after will confirm. If wrong, would bloat binary; not a blocker |
| A6 | sigstore-trust-root 0.7.0 has `tuf` feature enabled by default in the consumed configuration (so `PRODUCTION_TUF_ROOT` const is exported) | Pattern 3 + Don't Hand-Roll | Confirmed: `Cargo.lock:3732-3749` shows tough is unconditionally pulled, so the `tuf` feature is active for this consumer. If sigstore-verify upstream ever flips this default, the const access would break compile; nono-cli would need to add `sigstore-trust-root = { version = "0.7.0", features = ["tuf"] }` as a direct dep |

## Open Questions

1. **Exact `ureq::Body` reading API in 3.3.0**
   - What we know: ureq 3.x has a streamable `Body` type accessible via `Response::body_mut()`.
   - What's unclear: whether `read_to_vec()` is a direct method or requires going through `into_reader()`. Search of ureq source did not surface a single canonical pattern.
   - Recommendation: planner runs `cargo doc -p ureq --open` on first task and updates Example A accordingly. If `read_to_vec` is absent, use:
     ```rust
     let mut buf = Vec::new();
     resp.body_mut().into_reader().read_to_end(&mut buf)?;
     ```

2. **`async-trait` direct-dep need**
   - What we know: `async-trait` is transitively available via tough; impls of `#[async_trait]` on local types may or may not require the crate to be a direct dep depending on macro hygiene.
   - What's unclear: whether the `#[async_trait]` macro re-exports cleanly or needs `extern crate async_trait`.
   - Recommendation: Compile first; add as direct dep only if compile fails with "cannot find attribute macro `async_trait`". CLAUDE.md "lazy use of dead code" applies.

3. **Test fixture generation: hand-write vs `tuftool`**
   - What we know: D-50-08 mandates `StaticMapTransport` (in-memory). Fixture content is open.
   - What's unclear: whether the planner should check in pre-generated bytes (using `tuftool` once) or use `tough::editor::RepositoryEditor` at test runtime.
   - Recommendation: pre-generated check-in (Example C option 1) — simpler, no test-time dependency on tough's editor API stability. Planner generates these as a manual one-time step and commits them under `crates/nono-cli/tests/fixtures/tuf-repo-{happy,bad-sig,malformed}/`.

4. **Whether to bump `tough` major-version pin or float**
   - What we know: lockfile entry is exactly `0.22.0`. D-50-05 says version pin matches existing lockfile.
   - What's unclear: should the Cargo.toml declare `tough = "0.22"` (caret-range to 0.23) or `tough = "=0.22.0"` (exact pin)?
   - Recommendation: `tough = "0.22"` (caret range). Matching the lockfile's resolved version is what cargo does by default; pinning exact creates churn when sigstore-trust-root bumps. The lockfile keeps the same minor.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust toolchain (host) | All builds | ✓ | 1.85+ (ureq MSRV) — Cargo.toml workspace.rust-version is 1.77; need to verify workspace MSRV is ≥ 1.85 because ureq 3.3.0 declares `rust-version = "1.85"` (ureq-3.3.0/Cargo.toml:14). May need MSRV bump. | — |
| `tough 0.22.0` | Phase 50 chain-walk | ✓ (transitive in Cargo.lock:3727) | 0.22.0 | — |
| `ureq 3.x` with `platform-verifier` feature | Phase 50 HTTP transport | ✓ (declared in nono-cli/Cargo.toml:73) | 3.3.0 | — |
| `sigstore-trust-root 0.7.0` | Embedded `PRODUCTION_TUF_ROOT` const | ✓ (transitive via sigstore-verify) | 0.7.0 | — |
| `tokio 1.x` with `rt` feature | Async runtime for `tough` | ✓ (nono-cli/Cargo.toml:71) | 1.x | — |
| `x86_64-unknown-linux-gnu` rustup target | Cross-target clippy verification (D-50-13) | ⚠ (depends on dev host) | — | Live CI Linux Clippy lane on head SHA (see `.planning/templates/cross-target-verify-checklist.md`); D-50-13 says HARD pass, so PARTIAL deferral is **NOT** allowed for Phase 50 — verifier MUST run cross-target locally or wait for CI green |
| `x86_64-apple-darwin` rustup target | Cross-target clippy verification (D-50-13) | ⚠ (depends on dev host) | — | Same as above |
| `tuftool` (Bottlerocket TUF CLI) | One-time fixture generation (planner discretion) | ✗ likely not installed | — | Hand-craft fixtures using `tough::editor` at test-time, OR use a single-shot run on a separate machine to generate the bytes and commit them |

**MSRV note (critical):** ureq 3.3.0's `rust-version = "1.85"` (verified at `ureq-3.3.0/Cargo.toml:14`) may exceed the project's workspace MSRV (CLAUDE.md says 1.77 minimum). Either:
- The workspace MSRV is already implicitly higher (CLAUDE.md mentions "bumped in Phase 04 plan 02 to support safer Windows service/WFP handle bindings"); verify via `cat Cargo.toml | grep rust-version`.
- Or a Cargo.toml workspace MSRV bump is required. Planner adds this as a task if needed.

**Missing dependencies with no fallback:**
- Cross-target Linux/macOS rustup targets if `rustup target list --installed` does not show them; D-50-13 requires they be installed OR CI to confirm green.

**Missing dependencies with fallback:**
- `tuftool` — fallback is hand-crafted fixtures via `tough::editor` (planner-discretion option B).

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in `#[test]` + `#[tokio::test]` (async tests, since tough is async) |
| Config file | None (uses Cargo standard test target) |
| Quick run command | `cargo test -p nono-cli trust_refresh::tests --` |
| Full suite command | `make test` (workspace-wide) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| Req 1 | TUF chain-walk replaces upstream call | grep guard + happy-path test | `grep -rn 'TrustedRoot::production()' crates/nono-cli/src/` returns zero matches AND `cargo test -p nono-cli trust_refresh::tests::happy_path` | ❌ Wave 0 (test file `crates/nono-cli/src/trust_refresh.rs` doesn't exist yet) |
| Req 2 | ureq + platform-verifier used | unit test on agent construction + code review | `cargo test -p nono-cli trust_refresh::tests::agent_uses_platform_verifier` (or code-review checkbox if the agent builder is too short to unit-test meaningfully) | ❌ Wave 0 |
| Req 3 | TUF signature math via tough; bad-sig rejected | hermetic integration test with `StaticMapTransport` serving bad sig | `cargo test -p nono-cli trust_refresh::tests::bad_signature_rejected -- --nocapture` | ❌ Wave 0 |
| Req 4 | Byte-identical cache output | snapshot test | `cargo test -p nono-cli trust_refresh::tests::byte_identical_snapshot` | ❌ Wave 0 |
| Req 5 | ≥ 4 hermetic unit/integration tests pass on Win+Linux+macOS | full new test module | `cargo test -p nono-cli trust_refresh::tests --` (all 4+ pass) | ❌ Wave 0 |
| Req 6 | HUMAN-UAT corp-network success | manual | Run `nono setup --refresh-trust-root` on Windows corp-host; record in `50-VERIFICATION.md` | ❌ Wave 0 (`50-HUMAN-UAT.md` doesn't exist yet) |

### Sampling Rate

- **Per task commit:** `cargo test -p nono-cli trust_refresh::tests --` (4+ tests, all hermetic, < 5s total)
- **Per wave merge:** `make test` (full workspace), `make clippy` (lints)
- **Phase gate:** Full suite green + cross-target clippy green on all three targets (D-50-13) + HUMAN-UAT pass entry in `50-VERIFICATION.md` before `/gsd-verify-work`

### Wave 0 Gaps

- [ ] `crates/nono-cli/src/trust_refresh.rs` — new module file with production code + test module
- [ ] `crates/nono-cli/tests/fixtures/tuf-repo-happy/` — pre-generated minimal valid TUF repo (planner's discretion: generate via tuftool one-time OR programmatically via tough::editor at test setup)
- [ ] `crates/nono-cli/tests/fixtures/tuf-repo-bad-sig/` — variant with one byte flipped in N+1.root.json signature
- [ ] `crates/nono-cli/tests/fixtures/tuf-repo-malformed/` — variant with truncated/invalid JSON
- [ ] `crates/nono-cli/Cargo.toml` — add `tough = "0.22"` to `[dependencies]`; possibly `async-trait = "0.1"` if compile-test reveals it's needed
- [ ] Workspace `Cargo.toml` MSRV — bump `rust-version` to `1.85` if not already (ureq 3.3.0 requires it)
- [ ] `crates/nono-cli/src/main.rs` — add `mod trust_refresh;` declaration
- [ ] `.planning/phases/50-.../50-HUMAN-UAT.md` — single scenario per Req 6

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V6 Cryptography — signature verification | yes | `tough 0.22.0` does ALL signature math via its `Signed<Root>::verify_role` impl; nono provides ZERO crypto code. Hand-rolled verification is forbidden by SPEC Req 3 and the file diff is grep-guarded |
| V9 Communications — TLS cert validation | yes | `rustls-platform-verifier 0.6.x` (via ureq's `platform-verifier` feature) delegates to OS root store. nono does NOT build a custom rustls `ClientConfig` |
| V10 Malicious Software — supply-chain integrity | yes (this IS supply-chain code) | The whole point of the TUF chain walk is rollback-attack / fast-forward-attack resistance. tough's spec compliance is the control; not regressing it is the requirement |
| V4 Access Control | no | No new privileges granted; cache file written under existing `nono_home_dir()` (same path as Phase 32) |
| V5 Input Validation | partial | `TrustedRoot::from_json` does schema validation; tough's `serde_json::from_slice` does signature-bearing-JSON validation. New nono code only adds: URL parse, UTF-8 decode on target bytes, both wrapped in `?` |

### Known Threat Patterns for {TUF chain walk + corp-network HTTP}

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Rollback attack (attacker serves old root.json) | Tampering | tough's TUF spec compliance: version monotonicity check at `tough-0.22.0/src/lib.rs:794-803` |
| Fast-forward attack (attacker skips to forged future root) | Tampering | tough's `max_root_updates` limit (1024 default) + signature threshold per role |
| Endless-data attack (attacker streams unbounded bytes) | Denial of Service | tough's `Limits.max_root_size = 1 MiB` default (line 291) — applied to every fetched root.json |
| MITM with self-signed cert (corp proxy without enterprise CA) | Spoofing | rustls-platform-verifier rejects untrusted chains; user sees "transport error" not silent acceptance (fail-secure) |
| Cache poisoning of `<nono_home>/.nono/trust-root/tuf-cache/` | Tampering | tough's datastore is internal state for replay-attack prevention; tampering would cause next-load failures, not silent compromise. nono's only contract is to provide the directory path |
| Concurrent setup invocations write partial `trusted_root.json` | Tampering / Atomicity | EXISTING `setup.rs:857-860` pattern (`fs::write` is atomic on rename-on-write filesystems; on Windows, NTFS write-then-rename is not atomic by default). NOT regressed by Phase 50 — same write pattern as before |

## Sources

### Primary (HIGH confidence)

- `tough-0.22.0/src/transport.rs:46-49` — Transport trait definition (`#[async_trait]`, `Debug + DynClone + Send + Sync`)
- `tough-0.22.0/src/transport.rs:21-36` — `IntoVec` trait for stream collection
- `tough-0.22.0/src/lib.rs:117-247` — `RepositoryLoader` API (new, transport, datastore, load)
- `tough-0.22.0/src/lib.rs:206` — `RepositoryLoader::load() -> Result<Repository>` is async
- `tough-0.22.0/src/lib.rs:458-499` — `Repository::read_target` is async, returns `Option<Stream + IntoVec>`
- `tough-0.22.0/src/lib.rs:689-803` — `load_root` chain walk implementation (steps 5.2 + 5.3)
- `tough-0.22.0/src/http.rs:126-130` — Status code → `FileNotFound` mapping (403, 404, 410)
- `tough-0.22.0/src/http.rs:142-150` — Reference `HttpTransport` impl pattern for `Transport`
- `sigstore-trust-root-0.7.0/src/tuf.rs:48-60` — `DEFAULT_TUF_URL`, `PRODUCTION_TUF_ROOT`, `TRUSTED_ROOT_TARGET` consts
- `sigstore-trust-root-0.7.0/src/tuf.rs:349-407` — `TufClient::load_repository` + `read_target_from_repo` (direct pattern to port)
- `sigstore-trust-root-0.7.0/src/tuf.rs:478-540` — `TrustedRoot::production()` / `from_tuf()` flow (canonical reference)
- `sigstore-trust-root-0.7.0/src/trusted_root.rs:18-39` — `TrustedRoot` derives `Serialize + Deserialize`
- `sigstore-trust-root-0.7.0/src/trusted_root.rs:174-185` — `from_json` / `from_file` API
- `ureq-3.3.0/src/lib.rs:256-273` — Canonical `Agent::config_builder().tls_config(RootCerts::PlatformVerifier)` example
- `ureq-3.3.0/src/tls/mod.rs:294-312` — `RootCerts` enum (`PlatformVerifier` variant)
- `ureq-3.3.0/Cargo.toml:100` — `platform-verifier` feature flag wiring
- `ureq-3.3.0/Cargo.toml:14` — Rust MSRV 1.85 (POTENTIAL workspace MSRV bump required)
- `crates/nono-cli/Cargo.toml:73` — Existing ureq + platform-verifier feature declaration (no add needed)
- `crates/nono-cli/src/setup.rs:828-868` — Current `refresh_trust_root_step` (the call site to modify)
- `crates/nono-cli/src/setup.rs:888-919` — Phase 49 `from_file_step` (structural mirror for step shape)
- `crates/nono/src/trust/bundle.rs:113-167` — Cache contract (`load_trusted_root`, `load_production_trusted_root`, `check_trusted_root_freshness`) — UNCHANGED
- `Cargo.lock:3727-3749` — sigstore-trust-root 0.7.0 transitive deps including tough 0.22.0
- `.planning/debug/resolved/sigstore-tuf-fetch-transport.md` — Root cause analysis (reqwest 0.12.28 + webpki-roots)
- `.planning/debug/resolved/sigstore-trust-root-zero-sigs.md` — Predecessor chain-walk understanding
- `.planning/templates/cross-target-verify-checklist.md` — Cross-target clippy enforcement protocol

### Secondary (MEDIUM confidence)

- `ureq-3.3.0/src/agent.rs:89-99` — Agent is `Arc`-internals (cheap to clone) — verified by struct definition
- `tough-0.22.0/tests/data/tuf-reference-impl/metadata/` — Reference TUF repo layout (1.root.json, root.json, snapshot.json, targets.json, timestamp.json) — useful template for test fixtures
- `tough-0.22.0/tests/transport.rs:38-49` — `Transport` test pattern (file URL via DefaultTransport); informs StaticMapTransport shape

### Tertiary (LOW confidence)

- ureq 3.x `Body::read_to_vec()` API existence — open question A1; planner verifies via `cargo doc` before writing the task

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all versions verified against on-disk Cargo.lock + Cargo.toml + cargo registry source
- Architecture: HIGH — direct port of upstream `sigstore-trust-root-0.7.0/src/tuf.rs::TufClient` pattern, with two minimal substitutions
- Pitfalls: HIGH — five pitfalls cite specific upstream code locations; Pitfall 1 (async vs sync) is critical correction to CONTEXT.md
- Test fixture pattern: MEDIUM — `StaticMapTransport` shape is direct from `tough::Transport` trait, but fixture generation guidance has two valid options (planner picks)

**Research date:** 2026-05-21
**Valid until:** 2026-06-21 (30 days; tough/ureq/sigstore-trust-root all stable; sigstore TUF v15→v16 rotation expected after 2026-11-20 — refresh research if phase work slides past November)

## RESEARCH COMPLETE
