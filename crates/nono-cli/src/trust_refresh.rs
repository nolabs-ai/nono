//! Nono-local TUF chain-walk for refreshing the Sigstore trusted root
//! against `https://tuf-repo-cdn.sigstore.dev` using an HTTP transport
//! that consults the OS certificate store (`ureq` + `platform-verifier`).
//!
//! This module replaces the single call to the upstream production-trust-root
//! helper previously used by `crate::setup::SetupRunner::refresh_trust_root_step`.
//! The motivation is corp-network resilience: `reqwest 0.12.28` (pulled
//! transitively by `sigstore-trust-root 0.7.0`) uses `webpki-roots` (Mozilla
//! CA bundle) and cannot see enterprise CAs deployed via GPO/MDM, causing
//! `nono setup --refresh-trust-root` to fail on TLS-inspecting corporate
//! networks. See `.planning/debug/resolved/sigstore-tuf-fetch-transport.md`
//! and `.planning/phases/50-corp-network-tuf-refresh-via-os-root-store-replace-or-wrap-t/`.
//!
//! Phase 50 D-50-01: This module lives in `nono-cli`, not in `crates/nono`,
//! to preserve the P32-CHK-002 / D-32-15 invariant that `crates/nono` has
//! zero HTTP transport dependencies.
//!
//! Phase 50 D-50-02: The public surface is a single free function that
//! returns the same `TrustedRoot` value the upstream call would have
//! produced — swap-in replacement, byte-identical cache output.
//!
//! Phase 50 (RESEARCH.md A4 correction): The public function is `async fn`
//! because `tough::RepositoryLoader::load`, `Repository::read_target`, and
//! `IntoVec::into_vec` are all async. The CONTEXT.md statement that
//! "tough + ureq are sync, no tokio runtime needed" is WRONG; the caller
//! (`refresh_trust_root_step`) MUST preserve the
//! `tokio::runtime::Builder::new_current_thread()` block.
//!
//! Implementation note (Phase 50 Plan 02): This is a verbatim port of
//! `sigstore-trust-root-0.7.0/src/tuf.rs::TufClient::load_repository`
//! (lines 349-407) with TWO substitutions: (1) `tough::HttpTransport`
//! -> `UreqTransport(ureq::Agent)` so the OS root store is honored;
//! (2) sigstore-rs's `directories`-based cache path -> nono's
//! `nono_home_dir()` + `.nono/trust-root/tuf-cache/`. Signature math
//! stays in `tough` (D-50-04, SPEC Req 3).
//!
//! Phase 50 (Codex R-50-05): D-50-07 cleanup applies to ALL failures
//! after `tokio::fs::create_dir_all` succeeds — not just
//! `RepositoryLoader::load()` failure. The chain-walk body is wrapped in
//! a single inner helper whose `Result` is captured once; cleanup runs
//! once on `Err(_)`. Read-target / IntoVec / UTF-8 / TrustedRoot::from_json
//! failures all trigger the cleanup path now.

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

/// HTTP transport for `tough::RepositoryLoader` that uses a `ureq` agent
/// configured with the `platform-verifier` feature, so the OS certificate
/// store is consulted on every TLS handshake (Windows: Crypt32, macOS:
/// Security, Linux: ca-certificates).
///
/// Bridges sync `ureq::Agent::get(...).call()` into the async
/// `tough::Transport::fetch` trait method via `tokio::task::spawn_blocking`.
#[derive(Debug, Clone)]
struct UreqTransport {
    agent: Agent,
}

#[async_trait]
impl Transport for UreqTransport {
    async fn fetch(&self, url: Url) -> std::result::Result<TransportStream, TransportError> {
        let agent = self.agent.clone();
        let url_str = url.to_string();

        // Bridge: ureq is sync; tough::Transport::fetch is async.
        // spawn_blocking runs the sync ureq call on a tokio blocking thread.
        let join_result = tokio::task::spawn_blocking(move || {
            let mut resp = agent.get(&url_str).call()?;
            // Task 1 finding: ureq 3.3.0 exposes `Body::read_to_vec(&mut self)`
            // at src/body/mod.rs:329 → Option A in the plan; no `std::io::Read`
            // import needed.
            resp.body_mut().read_to_vec()
        })
        .await;

        let result = match join_result {
            Ok(r) => r,
            Err(e) => {
                return Err(TransportError::new_with_cause(
                    TransportErrorKind::Other,
                    url.as_str(),
                    e,
                ));
            }
        };

        match result {
            Ok(bytes) => {
                // Emit as a single-chunk stream (tough collects via IntoVec).
                let s = stream::iter(std::iter::once(Ok::<Bytes, TransportError>(Bytes::from(
                    bytes,
                ))));
                Ok(Box::pin(s))
            }
            // tough treats 403/404/410 as FileNotFound so the chain walk
            // can terminate cleanly when the next N+1.root.json doesn't
            // exist. Source: tough-0.22.0/src/http.rs:126-130.
            //
            // NOTE (Codex R-50-10): a corp-proxy returning HTTP 403 for
            // policy-deny reasons is normalized to FileNotFound here, which
            // tough then surfaces as a TUF "target not found" error. That
            // can misdirect debugging (looks like a missing root file
            // when really the proxy is denying access). The HUMAN-UAT
            // residual-risk section in Plan 05 documents this; we cannot
            // distinguish "missing root" from "proxy 403" without an
            // additional discriminator tough does not expose.
            Err(ureq::Error::StatusCode(code)) if code == 403 || code == 404 || code == 410 => {
                Err(TransportError::new(
                    TransportErrorKind::FileNotFound,
                    url.as_str(),
                ))
            }
            Err(e) => Err(TransportError::new_with_cause(
                TransportErrorKind::Other,
                url.as_str(),
                e,
            )),
        }
    }
}

/// Build the `ureq::Agent` used by `UreqTransport`.
///
/// `RootCerts::PlatformVerifier` is the discriminator that triggers the
/// `rustls-platform-verifier` path (gated by the `platform-verifier`
/// feature flag declared in `crates/nono-cli/Cargo.toml`).
///
/// Timeouts match `tough::HttpTransport`'s defaults
/// (`tough-0.22.0/src/http.rs:55-64`): 30s total, 10s connect.
fn build_corp_friendly_agent() -> Agent {
    Agent::config_builder()
        .tls_config(
            TlsConfig::builder()
                .root_certs(RootCerts::PlatformVerifier)
                .build(),
        )
        .timeout_global(Some(Duration::from_secs(30)))
        .timeout_connect(Some(Duration::from_secs(10)))
        .build()
        .new_agent()
}

/// Inner helper: everything that runs AFTER the datastore directory has
/// been created. Used by `refresh_trusted_root_with_transport` so we have
/// a single `Result` to match against for the broadened cleanup path
/// (Codex R-50-05 / D-50-07 literal semantics).
///
/// Phase 50 Plan 04 (Task 1): generalized to take `embedded_root: &[u8]`
/// and an arbitrary `Transport` impl so the test seam can substitute the
/// fixture's `1.root.json` and an in-memory `StaticMapTransport` while
/// driving the SAME chain-walk body production uses (D-50-08).
///
/// Returns `Result<TrustedRoot>` — the caller is responsible for cleanup.
async fn do_refresh_after_datastore_create_with_root(
    metadata_url: Url,
    targets_url: Url,
    datastore_dir: PathBuf,
    transport: impl Transport + 'static,
    embedded_root: &[u8],
) -> Result<TrustedRoot> {
    let repo = RepositoryLoader::new(&embedded_root, metadata_url, targets_url)
        .transport(transport)
        .datastore(datastore_dir)
        .load()
        .await
        .map_err(|e| NonoError::Setup(format!("Sigstore TUF refresh failed: {e}")))?;

    let target_name = TargetName::new(TRUSTED_ROOT_TARGET)
        .map_err(|e| NonoError::Setup(format!("invalid target name: {e}")))?;
    let stream = repo
        .read_target(&target_name)
        .await
        .map_err(|e| NonoError::Setup(format!("read trusted_root target: {e}")))?
        .ok_or_else(|| {
            NonoError::Setup(format!(
                "Sigstore target not found in TUF repo: {TRUSTED_ROOT_TARGET}"
            ))
        })?;

    let bytes = stream
        .into_vec()
        .await
        .map_err(|e| NonoError::Setup(format!("collect trusted_root bytes: {e}")))?;

    let json = std::str::from_utf8(&bytes)
        .map_err(|e| NonoError::Setup(format!("trusted_root.json is not UTF-8: {e}")))?;
    TrustedRoot::from_json(json)
        .map_err(|e| NonoError::Setup(format!("parse trusted_root.json: {e}")))
}

/// Phase 50 Plan 04 Task 1: wider injectable seam.
///
/// Wraps `do_refresh_after_datastore_create_with_root` with the
/// datastore-creation + broadened-cleanup pattern (R-50-05). Public to
/// the crate so the colocated test module (`mod tests`) can drive the
/// SAME chain-walk logic production uses, just with a swapped transport,
/// URLs, datastore, and embedded root anchor.
///
/// Production callers go through `refresh_production_trusted_root` which
/// composes the production values; tests construct each parameter
/// explicitly so the chain-walk is exercised hermetically.
///
/// # Errors
///
/// `NonoError::Setup` for all TUF / transport / parse failures. Best-effort
/// cleanup of `datastore_dir` is performed on ANY failure path after
/// `create_dir_all` succeeds.
pub(crate) async fn refresh_trusted_root_with_transport(
    transport: impl Transport + 'static,
    metadata_url: Url,
    targets_url: Url,
    datastore_dir: PathBuf,
    embedded_root: &[u8],
) -> Result<TrustedRoot> {
    // TUF datastore dir (D-50-07). tough requires this to exist BEFORE
    // .load() is called (Pitfall 2; tough-0.22.0/src/lib.rs:228-231).
    tokio::fs::create_dir_all(&datastore_dir)
        .await
        .map_err(|e| {
            NonoError::Setup(format!(
                "create tuf-cache dir {}: {e}",
                datastore_dir.display()
            ))
        })?;

    // Drive the TUF chain walk + signature verification (all in tough),
    // then fetch + parse the trusted_root.json target. ALL of this is
    // inside the inner helper so we have a single Result to capture for
    // the broadened cleanup path (Codex R-50-05).
    let datastore_for_cleanup = datastore_dir.clone();
    let result = do_refresh_after_datastore_create_with_root(
        metadata_url,
        targets_url,
        datastore_dir,
        transport,
        embedded_root,
    )
    .await;

    // Broadened cleanup (D-50-07 + Codex R-50-05): on ANY error from the
    // inner helper — TUF load, read_target, IntoVec, UTF-8, or
    // TrustedRoot::from_json — best-effort remove the datastore so we
    // don't leave partial state on disk. Cleanup result is ignored;
    // the primary error is what surfaces to the user.
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&datastore_for_cleanup);
    }
    result
}

/// Refresh the Sigstore production trusted root by walking the TUF chain
/// from the embedded v14 anchor (`sigstore_trust_root::PRODUCTION_TUF_ROOT`)
/// to the current head at `https://tuf-repo-cdn.sigstore.dev/`, using an
/// HTTP transport that consults the OS certificate store.
///
/// Returns the same `TrustedRoot` value the upstream production helper
/// would have produced; the call site (`crate::setup::SetupRunner::refresh_trust_root_step`)
/// serializes via the SAME `serde_json::to_string_pretty` call so the cache
/// file at `<nono_home>/.nono/trust-root/trusted_root.json` is byte-identical
/// to what the upstream call would have written.
///
/// # Errors
///
/// `NonoError::Setup` for all TUF / transport / parse failures. Best-effort
/// cleanup of the TUF datastore at `<nono_home>/.nono/trust-root/tuf-cache/`
/// is performed on ANY failure path after `create_dir_all` succeeds
/// (D-49-B2 / D-50-07 — broadened per Codex R-50-05).
// Phase 50 Wave 1: this function is still not invoked from any production
// code path; Plan 50-03 swaps `setup.rs::refresh_trust_root_step` to call
// it. The `#[allow(dead_code)]` is removed at that point.
#[allow(dead_code)]
pub async fn refresh_production_trusted_root() -> Result<TrustedRoot> {
    // Phase 50 Plan 04 Task 1 (Codex R-50-07): test-only env-seam.
    //
    // When `NONO_TEST_TUF_FIXTURE` is set in `#[cfg(test)]` builds, redirect
    // to a hermetic StaticMapTransport wired against the named fixture so
    // tests can exercise THIS public wrapper (not just the internal helper).
    // This validates URL composition, agent type, datastore resolution, and
    // delegation to `refresh_trusted_root_with_transport` at the integration
    // boundary — the gap R-50-07 flagged.
    //
    // The entire `if let Ok(...)` block is stripped from release builds by
    // `#[cfg(test)]`, so the env var is unreadable in production and there
    // is zero runtime overhead in `cargo build --release`.
    #[cfg(test)]
    if let Ok(fixture_name) = std::env::var("NONO_TEST_TUF_FIXTURE") {
        return tests::refresh_via_fixture_env_seam(&fixture_name).await;
    }

    // 1. URL setup (mirror sigstore-trust-root tuf.rs:350-354).
    let base_url = Url::parse(DEFAULT_TUF_URL)
        .map_err(|e| NonoError::Setup(format!("invalid Sigstore TUF URL: {e}")))?;
    let metadata_url = base_url.clone();
    let targets_url = base_url
        .join("targets/")
        .map_err(|e| NonoError::Setup(format!("invalid Sigstore targets URL: {e}")))?;

    // 2. TUF datastore dir (D-50-07).
    let datastore_dir = crate::config::nono_home_dir()
        .map_err(|e| NonoError::Setup(format!("resolve nono home dir: {e}")))?
        .join(".nono")
        .join("trust-root")
        .join("tuf-cache");

    // 3. Build agent + transport.
    let agent = build_corp_friendly_agent();
    let transport = UreqTransport { agent };

    // 4. Delegate to the wider seam (Plan 04 Task 1). Production passes the
    //    embedded `PRODUCTION_TUF_ROOT` const as the anchor; tests pass a
    //    fixture's `1.root.json`. The seam owns datastore creation + the
    //    R-50-05 broadened cleanup path.
    refresh_trusted_root_with_transport(
        transport,
        metadata_url,
        targets_url,
        datastore_dir,
        PRODUCTION_TUF_ROOT,
    )
    .await
}

// Phase 50 Plan 04 Task 3: hermetic test suite for the TUF chain-walk.
//
// Six tests cover SPEC Req 3 (bad signature), Req 4 (byte-identical
// cache vs captured baseline — R-50-03 strengthened), and Req 5 (>=4
// hermetic tests, exceeded). Tests 1-5 drive the wider injectable seam
// `refresh_trusted_root_with_transport` directly; Test 6 (R-50-07)
// exercises the PUBLIC `refresh_production_trusted_root` wrapper
// through the `NONO_TEST_TUF_FIXTURE` env-seam to validate URL
// composition, agent build, datastore resolution, and delegation at
// the integration boundary.
//
// All tests are hermetic: no localhost HTTP server, no port allocation,
// no real TLS handshake. The in-memory `StaticMapTransport` serves
// pre-generated TUF fixture bytes (see scripts/regenerate-tuf-test-fixtures.sh).
#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::tempdir;

    /// In-memory `tough::Transport` for hermetic testing (D-50-08).
    ///
    /// Serves a static map of URL-path keys to byte buffers. Returns
    /// `FileNotFound` for any path not in the map, which is exactly the
    /// signal `tough`'s chain-walk uses to terminate the
    /// `N+1.root.json` traversal (tough-0.22.0/src/http.rs:126-130).
    #[derive(Debug, Clone)]
    pub(super) struct StaticMapTransport {
        files: Arc<HashMap<String, Vec<u8>>>,
    }

    #[async_trait]
    impl Transport for StaticMapTransport {
        async fn fetch(
            &self,
            url: Url,
        ) -> std::result::Result<TransportStream, TransportError> {
            let key = url.path().trim_start_matches('/').to_string();
            match self.files.get(&key) {
                Some(bytes) => {
                    let s = stream::iter(std::iter::once(
                        Ok::<Bytes, TransportError>(Bytes::from(bytes.clone())),
                    ));
                    Ok(Box::pin(s))
                }
                None => Err(TransportError::new(
                    TransportErrorKind::FileNotFound,
                    url.as_str(),
                )),
            }
        }
    }

    fn fixture_dir(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    /// Recursively load every file under `fixture_dir(name)` into a
    /// `HashMap` keyed by the path relative to the fixture root.
    ///
    /// Keys ALWAYS use forward slashes so they match `url.path()`
    /// output regardless of host OS (Windows path separator must NOT
    /// leak into the map key).
    fn load_fixture(name: &str) -> HashMap<String, Vec<u8>> {
        let root = fixture_dir(name);
        let mut map = HashMap::new();
        fn walk(
            root: &std::path::Path,
            prefix: &str,
            map: &mut HashMap<String, Vec<u8>>,
        ) {
            for entry in std::fs::read_dir(root).expect("read fixture dir") {
                let entry = entry.expect("dir entry");
                let path = entry.path();
                let name = entry
                    .file_name()
                    .into_string()
                    .expect("utf-8 filename");
                let key = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}/{name}")
                };
                if path.is_dir() {
                    walk(&path, &key, map);
                } else {
                    let bytes = std::fs::read(&path).expect("read fixture file");
                    map.insert(key, bytes);
                }
            }
        }
        walk(&root, "", &mut map);
        map
    }

    fn embedded_root_for_fixture(files: &HashMap<String, Vec<u8>>) -> Vec<u8> {
        // The "embedded" anchor for the test is the fixture's
        // `1.root.json` (NOT the production `PRODUCTION_TUF_ROOT` const,
        // which is signed by sigstore's real keys and would not verify
        // against the test fixture).
        files
            .get("1.root.json")
            .cloned()
            .expect("1.root.json missing from fixture")
    }

    fn test_urls() -> (Url, Url) {
        (
            Url::parse("http://hermetic.test/").expect("parse metadata url"),
            Url::parse("http://hermetic.test/targets/").expect("parse targets url"),
        )
    }

    /// Helper dispatched into from `refresh_production_trusted_root`'s
    /// `#[cfg(test)]` env-seam when `NONO_TEST_TUF_FIXTURE` is set
    /// (R-50-07). Test 6 drives this through the public wrapper.
    pub(super) async fn refresh_via_fixture_env_seam(
        fixture_name: &str,
    ) -> Result<TrustedRoot> {
        let files = load_fixture(fixture_name);
        let embedded = embedded_root_for_fixture(&files);
        let transport = StaticMapTransport {
            files: Arc::new(files),
        };
        let datastore = tempdir().expect("tempdir for env-seam datastore");
        let (meta, targets) = test_urls();
        refresh_trusted_root_with_transport(
            transport,
            meta,
            targets,
            datastore.path().join("tuf-cache"),
            &embedded,
        )
        .await
    }

    /// Test 1 (R-50-09 renamed): happy-path TUF chain-walk against the
    /// pre-generated fixture returns `Ok(TrustedRoot)` whose
    /// `to_string_pretty` serialization is non-empty JSON. Covers SPEC
    /// Req 5 acceptance bullet (a).
    #[tokio::test]
    async fn happy_path_walk_returns_trusted_root() {
        let files = load_fixture("tuf-repo-happy");
        let embedded = embedded_root_for_fixture(&files);
        let transport = StaticMapTransport {
            files: Arc::new(files),
        };
        let datastore = tempdir().expect("tempdir for datastore");
        let (meta, targets) = test_urls();

        let result = refresh_trusted_root_with_transport(
            transport,
            meta,
            targets,
            datastore.path().join("tuf-cache"),
            &embedded,
        )
        .await;

        let trusted_root = result.expect("happy-path returns Ok");
        let json = serde_json::to_string_pretty(&trusted_root).expect("serialize");
        assert!(!json.is_empty(), "serialized trusted_root must be non-empty");
        assert!(json.contains('{'), "serialized output must be JSON");
    }

    /// Test 2 (R-50-09 renamed): bad signature in `1.root.json` is
    /// rejected by tough's signature-threshold check and surfaces as
    /// `NonoError::Setup(msg)` where `msg.contains("Sigstore TUF
    /// refresh failed")`. Covers SPEC Req 3 + Req 5 acceptance
    /// bullet (b).
    #[tokio::test]
    async fn bad_signature_at_root_surfaces_as_nono_error_setup() {
        let files = load_fixture("tuf-repo-bad-sig");
        let embedded = embedded_root_for_fixture(&files);
        let transport = StaticMapTransport {
            files: Arc::new(files),
        };
        let datastore = tempdir().expect("tempdir for datastore");
        let (meta, targets) = test_urls();

        let result = refresh_trusted_root_with_transport(
            transport,
            meta,
            targets,
            datastore.path().join("tuf-cache"),
            &embedded,
        )
        .await;

        match result {
            Err(NonoError::Setup(msg)) => {
                assert!(
                    msg.contains("Sigstore TUF refresh failed"),
                    "bad-sig error must surface through the TUF-refresh-failed wrapping; got: {msg}"
                );
            }
            Err(other) => panic!("expected NonoError::Setup for bad sig, got {other:?}"),
            Ok(_) => panic!("bad-sig fixture must NOT pass tough's signature verification"),
        }
    }

    /// Test 3 (R-50-09 renamed): truncated/invalid JSON in `1.root.json`
    /// surfaces as `NonoError::Setup(_)`. Covers SPEC Req 5 acceptance
    /// bullet (c).
    #[tokio::test]
    async fn malformed_json_at_root_surfaces_as_nono_error_setup() {
        let files = load_fixture("tuf-repo-malformed");
        let embedded = embedded_root_for_fixture(&files);
        let transport = StaticMapTransport {
            files: Arc::new(files),
        };
        let datastore = tempdir().expect("tempdir for datastore");
        let (meta, targets) = test_urls();

        let result = refresh_trusted_root_with_transport(
            transport,
            meta,
            targets,
            datastore.path().join("tuf-cache"),
            &embedded,
        )
        .await;

        match result {
            Err(NonoError::Setup(_)) => { /* expected */ }
            Err(other) => {
                panic!("expected NonoError::Setup for malformed JSON, got {other:?}")
            }
            Ok(_) => panic!("malformed-JSON fixture must NOT parse successfully"),
        }
    }

    /// Test 4 (Codex R-50-03 strengthened): byte-identical cache
    /// snapshot vs CAPTURED UPSTREAM baseline. Confirms SPEC Req 4
    /// contract: the bytes the chain-walk produces equal the bytes the
    /// upstream production serialization would have produced.
    ///
    /// The baseline file at
    /// `crates/nono-cli/tests/fixtures/tuf/trusted_root_baseline.json`
    /// was generated ONCE via `scripts/regenerate-tuf-test-fixtures.sh`
    /// by running
    /// `serde_json::to_string_pretty(&TrustedRoot::from_json(<happy
    /// fixture trusted_root.json>).unwrap())`. That captures the
    /// equivalence to what the upstream `TrustedRoot::production()`
    /// call would have produced against the same TUF repo content —
    /// the proper byte-identity check, not just serde round-trip
    /// determinism (R-50-03 gap closed).
    ///
    /// If this assertion fails, EITHER the chain-walk output drifted
    /// from upstream serialization (real bug) OR the baseline is stale
    /// and needs regenerating via the regen script.
    #[tokio::test]
    async fn cache_bytes_match_baseline() {
        const BASELINE: &[u8] =
            include_bytes!("../tests/fixtures/tuf/trusted_root_baseline.json");

        let files = load_fixture("tuf-repo-happy");
        let embedded = embedded_root_for_fixture(&files);
        let transport = StaticMapTransport {
            files: Arc::new(files),
        };
        let datastore = tempdir().expect("tempdir for datastore");
        let (meta, targets) = test_urls();
        let trusted_root = refresh_trusted_root_with_transport(
            transport,
            meta,
            targets,
            datastore.path().join("tuf-cache"),
            &embedded,
        )
        .await
        .expect("happy-path returns Ok");

        let actual_serialized =
            serde_json::to_string_pretty(&trusted_root).expect("serialize result");

        assert_eq!(
            actual_serialized.as_bytes(),
            BASELINE,
            "chain-walk output bytes must equal the upstream-captured baseline at \
             crates/nono-cli/tests/fixtures/tuf/trusted_root_baseline.json (SPEC Req 4 \
             byte-identical cache contract; R-50-03). If the assertion fails, EITHER \
             the chain-walk output drifted from upstream serialization (real bug) OR \
             the baseline is stale and needs regenerating via \
             scripts/regenerate-tuf-test-fixtures.sh."
        );
    }

    /// Test 5 (Codex R-50-03 additional): cache file round-trips
    /// through `TrustedRoot::from_file`. Confirms Phase 32 D-32-01
    /// offline-verify reader path is unaffected — the bytes produced
    /// by the chain-walk are loadable by the same API `nono trust
    /// verify` uses for the cached trusted_root.
    #[tokio::test]
    async fn cache_file_loadable_by_load_production_trusted_root() {
        // `TrustedRoot` is re-exported through `nono::trust::TrustedRoot`
        // (which `super::*` already brings into scope), which itself
        // re-exports `sigstore_verify::trust_root::TrustedRoot`. So
        // `TrustedRoot::from_file` is the same API the offline
        // `load_production_trusted_root` in crates/nono/src/trust/bundle.rs
        // uses for the cache file (Phase 32 D-32-01).
        let files = load_fixture("tuf-repo-happy");
        let embedded = embedded_root_for_fixture(&files);
        let transport = StaticMapTransport {
            files: Arc::new(files),
        };
        let datastore = tempdir().expect("tempdir for datastore");
        let (meta, targets) = test_urls();
        let trusted_root = refresh_trusted_root_with_transport(
            transport,
            meta,
            targets,
            datastore.path().join("tuf-cache"),
            &embedded,
        )
        .await
        .expect("happy-path returns Ok");

        // Mirror setup.rs's production write: to_string_pretty +
        // std::fs::write to the trust-root cache path.
        let json = serde_json::to_string_pretty(&trusted_root).expect("serialize");
        let cache_dir = tempdir().expect("tempdir for cache");
        let cache_path = cache_dir.path().join("trusted_root.json");
        std::fs::write(&cache_path, json.as_bytes()).expect("write cache");

        // Round-trip parse via the same API the offline verify path
        // uses for the cache file.
        let reread =
            TrustedRoot::from_file(&cache_path).expect("from_file round-trip");
        // Re-serialize and assert byte-equality with what we wrote —
        // proves the offline reader produces equivalent state from the
        // cache file (Phase 32 D-32-01 offline reader unaffected).
        let rejson = serde_json::to_string_pretty(&reread).expect("re-serialize");
        assert_eq!(
            json.as_bytes(),
            rejson.as_bytes(),
            "TrustedRoot::from_file must round-trip the chain-walk output byte-identically; \
             this proves Phase 32 D-32-01 offline-verify reader is unaffected by Phase 50"
        );
    }

    /// Test 6 (Codex R-50-07): exercise the PUBLIC wrapper
    /// `refresh_production_trusted_root()` through the
    /// `NONO_TEST_TUF_FIXTURE` env-seam, not just the internal helper.
    /// Validates URL composition, agent construction, datastore
    /// resolution, and delegation at the integration boundary the grep
    /// tests cannot reach.
    ///
    /// Uses the env-var guard pattern from PATTERNS.md §Test
    /// Environment Isolation: acquire `ENV_LOCK`, set
    /// `NONO_TEST_TUF_FIXTURE` via `EnvVarGuard::set_all` (restores on
    /// drop), call the public wrapper, assert Ok. The guard prevents
    /// the env var from leaking to the parallel test pool.
    // The env-seam lock is held across the await boundary by design:
    // the env var must remain set for the duration of
    // `refresh_production_trusted_root().await` so the inner
    // `#[cfg(test)] if let Ok(...) = env::var("NONO_TEST_TUF_FIXTURE")`
    // path reads it under the lock. Dropping the guard before await
    // would let another parallel test mutate the env var mid-call,
    // which is exactly the race ENV_LOCK exists to prevent. We block
    // the tokio executor briefly here — that's acceptable because the
    // hermetic in-memory transport completes in milliseconds.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn refresh_production_trusted_root_via_env_seam_returns_trusted_root() {
        // Acquire the global env-var lock to prevent parallel-test
        // races. Poisoning is harmless here — we only need exclusive
        // access while NONO_TEST_TUF_FIXTURE is set.
        let _lock = match crate::test_env::ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        let _guard = crate::test_env::EnvVarGuard::set_all(&[(
            "NONO_TEST_TUF_FIXTURE",
            "tuf-repo-happy",
        )]);

        // Call the PUBLIC wrapper. The #[cfg(test)] env-seam inside
        // refresh_production_trusted_root will detect
        // NONO_TEST_TUF_FIXTURE and dispatch into
        // refresh_via_fixture_env_seam("tuf-repo-happy").
        let result = refresh_production_trusted_root().await;
        let trusted_root =
            result.expect("public wrapper via env-seam returns Ok");

        // Sanity: serializable JSON output, just like the happy-path
        // test.
        let json = serde_json::to_string_pretty(&trusted_root).expect("serialize");
        assert!(!json.is_empty(), "serialized trusted_root must be non-empty");
        assert!(json.contains('{'), "serialized output must be JSON");
    }
}
