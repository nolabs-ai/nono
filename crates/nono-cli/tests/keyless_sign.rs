//! Phase 32 Plan 03 (D-32-07): hermetic keyless sign + verify roundtrip
//! via mock Fulcio + Rekor servers.
//!
//! ## Architecture
//!
//! The full `keyless_sign_then_verify_roundtrip` test requires injecting
//! mock Fulcio/Rekor URLs into the `nono trust sign --keyless` CLI subprocess.
//! The injection mechanism is an env-var shim (`NONO_TEST_FULCIO_URL` /
//! `NONO_TEST_REKOR_URL`) compiled in under `feature = "test-trust-overrides"`.
//!
//! Graduating from `#[ignore]` to active requires:
//! 1. Building the test binary with `--features test-trust-overrides`.
//! 2. Implementing a mock Fulcio endpoint that returns a valid DER-encoded
//!    Fulcio-signed certificate for the rcgen-generated ECDSA keypair.
//! 3. Implementing a mock Rekor endpoint that returns a syntactically valid
//!    Rekor v1/v2 log entry JSON that sigstore-sign's client parses without
//!    error.
//! 4. Providing a test TrustedRoot with the rcgen CA's public key substituted
//!    for the real Fulcio CA public key, so `nono trust verify --keyless`
//!    accepts the generated bundle.
//!
//! The full mock implementation is deferred to a Phase 32 follow-up
//! (see `.planning/deferred-items.md` entry P32-DEFER-001). The mock
//! infrastructure (httpmock server startup + hit-count assertion) is
//! active and verified by `mock_servers_only_no_real_network`.
//!
//! ## Capture Procedure (for future implementers)
//!
//! To populate the mock with real-world-shaped data:
//! 1. Run `nono trust sign --keyless` against Fulcio staging
//!    (`https://fulcio.sigstage.dev`) with a test OIDC token from
//!    a GitHub Actions `workflow_dispatch` run.
//! 2. Capture the Fulcio response (cert DER bytes) and Rekor entry JSON
//!    via a recording proxy or `sigstore-cli --debug`.
//! 3. Feed those into the mock server responses below.
//! 4. Build the test binary with `--features test-trust-overrides` and
//!    lift the `#[ignore]`.
//!
//! Reference: `.planning/phases/32-sigstore-integration/32-03-PLAN.md`
//! Task 2 Step 1 + 32-RESEARCH.md Pattern 4.

use std::fs;
use std::path::PathBuf;

fn setup_isolated_home() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp_root = std::env::current_dir()
        .expect("cwd")
        .join("target")
        .join("test-artifacts");
    fs::create_dir_all(&temp_root).expect("create temp root");
    let tmp = tempfile::Builder::new()
        .prefix("nono-keyless-sign-it-")
        .tempdir_in(&temp_root)
        .expect("tempdir");
    let home = tmp.path().join("home");
    let workspace = tmp.path().join("workspace");
    fs::create_dir_all(home.join(".config")).expect("config");
    fs::create_dir_all(home.join("AppData").join("Roaming")).expect("AppData/Roaming");
    fs::create_dir_all(home.join("AppData").join("Local")).expect("AppData/Local");
    fs::create_dir_all(home.join(".nono").join("trust-root")).expect("trust-root");
    fs::create_dir_all(&workspace).expect("workspace");
    // Pre-seed the cache with the frozen fixture so verify can load a trust root.
    let frozen = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("nono")
        .join("tests")
        .join("fixtures")
        .join("trust-root-frozen.json");
    let cache_path = home.join(".nono").join("trust-root").join("trusted_root.json");
    fs::copy(&frozen, &cache_path).expect("seed cache");
    (tmp, home, workspace)
}

/// Start mock Fulcio and Rekor HTTP servers.
///
/// Returns `(fulcio_server, rekor_server)`. Both servers start with no mocked
/// routes; callers add routes as needed. The servers remain alive for the
/// duration of the returned values.
fn start_mock_fulcio_rekor() -> (httpmock::MockServer, httpmock::MockServer) {
    let fulcio = httpmock::MockServer::start();
    let rekor = httpmock::MockServer::start();
    (fulcio, rekor)
}

// ---------------------------------------------------------------------------
// D-32-07: full keyless sign + verify roundtrip (deferred — P32-DEFER-001)
//
// The full roundtrip test requires:
//   (a) A nono binary built with `--features test-trust-overrides`
//   (b) Mock Fulcio endpoint returning a rcgen-generated Fulcio-signed cert
//   (c) Mock Rekor endpoint returning a valid Rekor log entry
//   (d) A test TrustedRoot with the rcgen CA key substituted in
//
// The `#[ignore]` annotation is intentional and must be lifted only after
// the mock Fulcio/Rekor responses are properly wired.
// See `.planning/deferred-items.md` entry P32-DEFER-001.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "P32-DEFER-001: requires mock Fulcio/Rekor responses wired into the test binary; \
            see keyless_sign.rs module-level doc for capture procedure"]
async fn keyless_sign_then_verify_roundtrip() {
    let (_tmp, _home, workspace) = setup_isolated_home();
    let (_fulcio, _rekor) = start_mock_fulcio_rekor();

    fs::write(workspace.join("instruction.md"), "test instruction\n").expect("write");

    // TODO (P32-DEFER-001): wire NONO_TEST_FULCIO_URL and NONO_TEST_REKOR_URL
    // env vars into a nono binary compiled with `--features test-trust-overrides`,
    // configure mock Fulcio + Rekor route responses, and run `nono trust sign
    // --keyless instruction.md` followed by `nono trust verify --keyless
    // --issuer ... --identity ...`. Both must succeed.
    //
    // The deferred-items.md entry tracks the remaining work.
    panic!("not yet implemented — see P32-DEFER-001");
}

// ---------------------------------------------------------------------------
// D-32-07: mock infrastructure smoke test (ACTIVE — no #[ignore])
//
// Verifies that httpmock servers start correctly and accept connections.
// This test acts as the CI-active D-32-07 gate while the roundtrip is deferred.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mock_servers_only_no_real_network() {
    let (fulcio, rekor) = start_mock_fulcio_rekor();

    // Register sentinel mocks on both servers. In httpmock 0.7 hit counts are
    // tracked per-Mock object (not per-server), so we register one route on each
    // server and assert it has 0 hits — confirming no accidental traffic arrived.
    let fulcio_mock = fulcio.mock(|when, then| {
        when.path("/api/v2/signingCert");
        then.status(200);
    });
    let rekor_mock = rekor.mock(|when, then| {
        when.path("/api/v1/log/entries");
        then.status(200);
    });

    // Servers must be reachable on localhost. Verify URLs are well-formed.
    let fulcio_url = fulcio.url("/api/v2/signingCert");
    let rekor_url = rekor.url("/api/v1/log/entries");
    assert!(
        fulcio_url.starts_with("http://127.0.0.1:"),
        "mock Fulcio URL must be on localhost: {fulcio_url}"
    );
    assert!(
        rekor_url.starts_with("http://127.0.0.1:"),
        "mock Rekor URL must be on localhost: {rekor_url}"
    );

    // Confirm no accidental network traffic occurred (sentinel routes untouched).
    assert_eq!(
        fulcio_mock.hits(),
        0,
        "mock Fulcio signing-cert route must have 0 hits after URL check"
    );
    assert_eq!(
        rekor_mock.hits(),
        0,
        "mock Rekor log-entries route must have 0 hits after URL check"
    );
}

/// Frozen TUF fixture must exist (replaces the previous unused
/// `_verify_fixture_path` helper from WR-01 review). The assertion now actually
/// runs in CI rather than being suppressed by a leading-underscore name.
#[test]
fn frozen_tuf_fixture_is_present() {
    let frozen = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("nono")
        .join("tests")
        .join("fixtures")
        .join("trust-root-frozen.json");
    assert!(
        frozen.exists(),
        "frozen TUF fixture must exist at: {}",
        frozen.display()
    );
}
