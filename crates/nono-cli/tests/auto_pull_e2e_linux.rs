//! Phase 37 Plan 37-05 — Auto-pull e2e integration tests.
//!
//! Verifies REQ-PKGS-04 acceptance #1, #2, #3, #4, plus a 5th test for
//! non-Policy pack rejection (researcher Open Q3 — ~30 LOC additional
//! coverage). Linux-only because the workflow that runs this test pins to
//! ubuntu-24.04 and the production signing path is exercised via the
//! GitHub Actions OIDC token at CI time (D-13 + D-15).
//!
//! File path is LOCKED at this location per D-16.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::net::{Shutdown, TcpListener};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use tempfile::TempDir;

const NONO_BIN: &str = env!("CARGO_BIN_EXE_nono");

// ---------------------------------------------------------------------------
// EnvGuard RAII — save/restore env vars per CLAUDE.md "tests run in parallel
// within the same process" rule + Pattern B.
// ---------------------------------------------------------------------------

pub(crate) struct EnvGuard {
    key: String,
    prev: Option<String>,
}

impl EnvGuard {
    pub(crate) fn set(key: &str, val: &str) -> Self {
        let prev = std::env::var(key).ok();
        std::env::set_var(key, val);
        Self {
            key: key.into(),
            prev,
        }
    }

    pub(crate) fn remove(key: &str) -> Self {
        let prev = std::env::var(key).ok();
        std::env::remove_var(key);
        Self {
            key: key.into(),
            prev,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.prev.take() {
            Some(v) => std::env::set_var(&self.key, v),
            None => std::env::remove_var(&self.key),
        }
    }
}

// ---------------------------------------------------------------------------
// Multi-endpoint mock TCP server — extends Phase 26-02's spawn_one_shot_server
// pattern (registry_client::tests::spawn_one_shot_server, 50 LOC base).
// NO mockito dev-dep added (D-14: portable-subset constraint preserved).
// ---------------------------------------------------------------------------

/// Spawn an HTTP mock that routes by URL path. Returns
/// `(base_url, JoinHandle, request_counter)`. Accepts up to
/// `routes.len() * 3 + 2` connections then exits (sufficient for the
/// longest auto-pull flow: bundle.json + manifest.json + artifact +
/// retry headroom).
///
/// Routes are a path→(status, body) map. A request whose path does not
/// match any route receives a 404 with body `"not found"`. This shape lets
/// `auto_pull_unknown_name_fails_closed` (Task 2) exercise the fail-closed
/// path with an empty route table.
pub(crate) fn spawn_multi_endpoint_server(
    routes: HashMap<String, (u16, Vec<u8>)>,
) -> (String, thread::JoinHandle<()>, Arc<Mutex<u32>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let addr = listener.local_addr().expect("local_addr");
    let base_url = format!("http://{}", addr);
    let counter = Arc::new(Mutex::new(0u32));
    let counter_clone = Arc::clone(&counter);

    let handle = thread::spawn(move || {
        let max_connections = routes.len() * 3 + 2;
        for accept in listener.incoming().take(max_connections) {
            let mut stream = match accept {
                Ok(s) => s,
                Err(_) => return,
            };
            *counter_clone.lock().unwrap() += 1;

            let mut buf = [0u8; 4096];
            let mut accumulated = Vec::with_capacity(4096);
            loop {
                let n = match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                accumulated.extend_from_slice(&buf[..n]);
                if accumulated.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
                if accumulated.len() > 64 * 1024 {
                    break;
                }
            }

            let request_line = std::str::from_utf8(&accumulated)
                .ok()
                .and_then(|s| s.lines().next())
                .unwrap_or("");
            let path = request_line.split_whitespace().nth(1).unwrap_or("/");

            let (status, body) = routes
                .get(path)
                .cloned()
                .unwrap_or((404, b"not found".to_vec()));
            let status_text = match status {
                200 => "OK",
                404 => "Not Found",
                500 => "Internal Server Error",
                _ => "Status",
            };
            let response_head = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                status,
                status_text,
                body.len()
            );
            let _ = stream.write_all(response_head.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
            let _ = stream.shutdown(Shutdown::Both);
        }
    });

    (base_url, handle, counter)
}

// ---------------------------------------------------------------------------
// Fixture loader — reads the CI-signed pack from NONO_FIXTURE_PACK_DIR.
// Task 4's CI workflow step populates this dir before invoking the tests.
// ---------------------------------------------------------------------------

pub(crate) fn fixture_pack_dir() -> Option<std::path::PathBuf> {
    let path = std::env::var("NONO_FIXTURE_PACK_DIR").ok()?;
    let pb = std::path::PathBuf::from(path);
    if pb.is_dir() {
        Some(pb)
    } else {
        None
    }
}

pub(crate) fn read_fixture(name: &str) -> Vec<u8> {
    let dir = fixture_pack_dir().expect(
        "NONO_FIXTURE_PACK_DIR not set — run via Phase 37 CI workflow OR locally with sigstore-sign keyless",
    );
    std::fs::read(dir.join(name)).expect("read fixture file")
}

// ---------------------------------------------------------------------------
// Helper smoke test — verifies the mock server helper end-to-end without
// invoking the nono binary. Lets `cargo test --no-run` + a single
// `cargo test spawn_multi_endpoint_server_smoke` prove the scaffold works
// before Tasks 2 + 3 add their tests.
// ---------------------------------------------------------------------------

#[test]
fn spawn_multi_endpoint_server_smoke() {
    use std::net::TcpStream;

    let mut routes = HashMap::new();
    routes.insert("/ping".to_string(), (200, b"pong".to_vec()));
    let (base_url, _handle, counter) = spawn_multi_endpoint_server(routes);

    // Parse "http://127.0.0.1:PORT" -> "127.0.0.1:PORT".
    let addr_part = base_url.trim_start_matches("http://");
    let mut stream = TcpStream::connect(addr_part).expect("connect mock");
    stream
        .write_all(b"GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write");
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    let resp_str = String::from_utf8_lossy(&response);

    assert!(
        resp_str.contains("pong"),
        "expected pong in response; got: {resp_str}"
    );
    assert_eq!(
        *counter.lock().unwrap(),
        1,
        "expected exactly 1 request"
    );
}

// ---------------------------------------------------------------------------
// REQ-PKGS-04 acceptance #1: happy path. Auto-pull succeeds against a signed
// fixture pack served by the mock registry. SKIPs when NONO_FIXTURE_PACK_DIR
// is unset (i.e., running outside the Phase 37 CI workflow).
// ---------------------------------------------------------------------------

#[test]
fn auto_pull_happy_path_mock() {
    let Some(_dir) = fixture_pack_dir() else {
        eprintln!("SKIP: NONO_FIXTURE_PACK_DIR not set — Phase 37 CI workflow required");
        return;
    };

    let tmp_home = TempDir::new().expect("tempdir");
    let _g_home = EnvGuard::set("NONO_TEST_HOME", tmp_home.path().to_str().unwrap());
    let _g_no_pull = EnvGuard::remove("NONO_NO_AUTO_PULL");

    let bundle_body = read_fixture("bundle.json");
    let manifest_body = read_fixture("manifest.json");
    let artifact_body = read_fixture("artifact.tar.gz");
    let sigstore_body = read_fixture("artifact.tar.gz.sigstore.json");

    let mut routes = HashMap::new();
    routes.insert("/bundle.json".into(), (200, bundle_body));
    routes.insert(
        "/mock-ns/mock-pack/manifest.json".into(),
        (200, manifest_body),
    );
    routes.insert(
        "/mock-ns/mock-pack/artifact.tar.gz".into(),
        (200, artifact_body),
    );
    routes.insert(
        "/mock-ns/mock-pack/artifact.tar.gz.sigstore.json".into(),
        (200, sigstore_body),
    );

    let (base_url, _handle, counter) = spawn_multi_endpoint_server(routes);
    let _g_reg = EnvGuard::set("NONO_REGISTRY", &base_url);

    let output = Command::new(NONO_BIN)
        .args([
            "run",
            "--profile",
            "mock-ns/mock-pack",
            "--",
            "/bin/true",
        ])
        .output()
        .expect("spawn nono");

    let req_count = *counter.lock().unwrap();
    assert!(
        output.status.success(),
        "auto-pull happy path failed; stdout={} stderr={} req_count={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        req_count
    );
    assert!(
        req_count > 0,
        "expected at least 1 request to mock registry; got 0"
    );
}

// ---------------------------------------------------------------------------
// REQ-PKGS-04 acceptance #2: fail-closed on unknown name. The mock registry
// serves 404 for every path; the nono binary must exit non-zero with a
// ProfileNotFound-flavored error, and must NOT continue retrying past a
// reasonable bound (request_count <= 2 — production code may issue 1-2
// lookups before giving up).
// ---------------------------------------------------------------------------

#[test]
fn auto_pull_unknown_name_fails_closed() {
    let tmp_home = TempDir::new().expect("tempdir");
    let _g_home = EnvGuard::set("NONO_TEST_HOME", tmp_home.path().to_str().unwrap());
    let _g_no_pull = EnvGuard::remove("NONO_NO_AUTO_PULL");

    // Mock registry returns 404 for everything.
    let routes: HashMap<String, (u16, Vec<u8>)> = HashMap::new();
    let (base_url, _handle, counter) = spawn_multi_endpoint_server(routes);
    let _g_reg = EnvGuard::set("NONO_REGISTRY", &base_url);

    let output = Command::new(NONO_BIN)
        .args([
            "run",
            "--profile",
            "not-a-namespace/totally-fake-pack",
            "--",
            "/bin/true",
        ])
        .output()
        .expect("spawn nono");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "unknown profile must fail; stderr={stderr}"
    );
    assert!(
        stderr.contains("profile not found")
            || stderr.contains("Profile not found")
            || stderr.contains("ProfileNotFound")
            || stderr.contains("not found"),
        "expected ProfileNotFound-like error; got: {stderr}"
    );

    let req_count = *counter.lock().unwrap();
    assert!(
        req_count <= 2,
        "fail-closed semantics: expected at most 2 requests for unknown name; got {req_count}"
    );
}

// ---------------------------------------------------------------------------
// REQ-PKGS-04 acceptance #4: --no-auto-pull suppression. The mock registry
// is available BUT the flag must prevent any network request to it; the
// binary falls back to ProfileNotFound. The D-11 diagnostic-formatter
// footer must mention --no-auto-pull so the user can self-diagnose.
// ---------------------------------------------------------------------------

#[test]
fn auto_pull_no_auto_pull_flag_falls_back_to_profile_not_found() {
    let tmp_home = TempDir::new().expect("tempdir");
    let _g_home = EnvGuard::set("NONO_TEST_HOME", tmp_home.path().to_str().unwrap());
    let _g_no_pull = EnvGuard::remove("NONO_NO_AUTO_PULL");

    // Mock registry exists BUT the flag should prevent any request to it.
    let routes: HashMap<String, (u16, Vec<u8>)> = HashMap::new();
    let (base_url, _handle, counter) = spawn_multi_endpoint_server(routes);
    let _g_reg = EnvGuard::set("NONO_REGISTRY", &base_url);

    let output = Command::new(NONO_BIN)
        .args([
            "run",
            "--no-auto-pull",
            "--profile",
            "mock-ns/mock-pack",
            "--",
            "/bin/true",
        ])
        .output()
        .expect("spawn nono");

    assert!(
        !output.status.success(),
        "--no-auto-pull must fall back to ProfileNotFound"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("profile not found")
            || stderr.contains("Profile not found")
            || stderr.contains("ProfileNotFound")
            || stderr.contains("not found"),
        "expected ProfileNotFound error; got: {stderr}"
    );
    // Phase 37 D-11 footer: diagnostic_formatter should mention --no-auto-pull.
    assert!(
        stderr.contains("--no-auto-pull") || stderr.contains("no-auto-pull"),
        "expected D-11 footer mentioning --no-auto-pull; got: {stderr}"
    );

    // REQ-PKGS-04 acceptance #4: no network call when flag is set.
    let req_count = *counter.lock().unwrap();
    assert_eq!(
        req_count, 0,
        "expected 0 requests with --no-auto-pull; got {req_count}"
    );
}

// ---------------------------------------------------------------------------
// REQ-PKGS-04 acceptance #3: signature failure aborts. CI signs the fixture
// pack at runtime; the test corrupts the artifact bytes mid-transit so the
// SHA-256 / sigstore bundle verification fails. The binary must exit
// non-zero with a signature/verification-flavored error AND the install
// directory must NOT contain package.json (verification aborts BEFORE
// install lands any bytes in the package store).
// ---------------------------------------------------------------------------

#[test]
fn auto_pull_signature_failure_aborts() {
    let Some(_dir) = fixture_pack_dir() else {
        eprintln!("SKIP: NONO_FIXTURE_PACK_DIR not set — Phase 37 CI workflow required");
        return;
    };

    let tmp_home = TempDir::new().expect("tempdir");
    let _g_home = EnvGuard::set("NONO_TEST_HOME", tmp_home.path().to_str().unwrap());
    let _g_no_pull = EnvGuard::remove("NONO_NO_AUTO_PULL");

    let bundle_body = read_fixture("bundle.json");
    let manifest_body = read_fixture("manifest.json");
    // CORRUPTED artifact — flip the first byte; SHA-256 will mismatch.
    let mut artifact_body = read_fixture("artifact.tar.gz");
    if !artifact_body.is_empty() {
        artifact_body[0] ^= 0xFF;
    }
    let sigstore_body = read_fixture("artifact.tar.gz.sigstore.json");

    let mut routes = HashMap::new();
    routes.insert("/bundle.json".into(), (200, bundle_body));
    routes.insert(
        "/mock-ns/mock-pack/manifest.json".into(),
        (200, manifest_body),
    );
    routes.insert(
        "/mock-ns/mock-pack/artifact.tar.gz".into(),
        (200, artifact_body),
    );
    routes.insert(
        "/mock-ns/mock-pack/artifact.tar.gz.sigstore.json".into(),
        (200, sigstore_body),
    );

    let (base_url, _handle, _counter) = spawn_multi_endpoint_server(routes);
    let _g_reg = EnvGuard::set("NONO_REGISTRY", &base_url);

    let output = Command::new(NONO_BIN)
        .args([
            "run",
            "--profile",
            "mock-ns/mock-pack",
            "--",
            "/bin/true",
        ])
        .output()
        .expect("spawn nono");

    assert!(
        !output.status.success(),
        "signature failure must abort; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lower = stderr.to_lowercase();
    assert!(
        lower.contains("signature")
            || lower.contains("verif")
            || lower.contains("digest")
            || lower.contains("trust"),
        "expected signature/verification-flavored error; got: {stderr}"
    );

    // Phase 37 D-16 + Phase 27.1: NONO_TEST_HOME plumbing resolves the
    // package install directory under <NONO_TEST_HOME>/.config/nono/packages/...
    // (see crates/nono-cli/src/profile/mod.rs::resolve_user_config_dir and
    // crates/nono-cli/src/package.rs::package_install_dir).
    let install_check = tmp_home
        .path()
        .join(".config")
        .join("nono")
        .join("packages")
        .join("mock-ns")
        .join("mock-pack")
        .join("package.json");
    assert!(
        !install_check.exists(),
        "signature failure must abort BEFORE install; found {install_check:?}"
    );
}

// ---------------------------------------------------------------------------
// Researcher Open Q3 #5: non-Policy pack rejection. CI emits a separate
// fixture manifest with pack_type="agent" (the only other PackType variant
// per package.rs:80-83). The binary must reject the pack — either via
// load_registry_profile's pack-type check (profile/mod.rs:2322-2330) or
// via signature failure if the signing step signs only the Policy manifest
// (the mutated manifest will invalidate the bundle). EITHER rejection is
// fail-closed — the test accepts both because the LOCKED requirement is
// rejection, not a specific check-ordering path.
// ---------------------------------------------------------------------------

#[test]
fn auto_pull_rejects_non_policy_pack_type() {
    let Some(dir) = fixture_pack_dir() else {
        eprintln!("SKIP: NONO_FIXTURE_PACK_DIR not set — Phase 37 CI workflow required");
        return;
    };
    if !dir.join("manifest-non-policy.json").is_file() {
        eprintln!(
            "SKIP: manifest-non-policy.json missing from fixture dir — Task 4 CI step did not generate it"
        );
        return;
    }

    let tmp_home = TempDir::new().expect("tempdir");
    let _g_home = EnvGuard::set("NONO_TEST_HOME", tmp_home.path().to_str().unwrap());
    let _g_no_pull = EnvGuard::remove("NONO_NO_AUTO_PULL");

    let bundle_body = read_fixture("bundle.json");
    let manifest_body = read_fixture("manifest-non-policy.json");
    let artifact_body = read_fixture("artifact.tar.gz");
    let sigstore_body = read_fixture("artifact.tar.gz.sigstore.json");

    let mut routes = HashMap::new();
    routes.insert("/bundle.json".into(), (200, bundle_body));
    routes.insert(
        "/mock-ns/mock-pack/manifest.json".into(),
        (200, manifest_body),
    );
    routes.insert(
        "/mock-ns/mock-pack/artifact.tar.gz".into(),
        (200, artifact_body),
    );
    routes.insert(
        "/mock-ns/mock-pack/artifact.tar.gz.sigstore.json".into(),
        (200, sigstore_body),
    );

    let (base_url, _handle, _counter) = spawn_multi_endpoint_server(routes);
    let _g_reg = EnvGuard::set("NONO_REGISTRY", &base_url);

    let output = Command::new(NONO_BIN)
        .args([
            "run",
            "--profile",
            "mock-ns/mock-pack",
            "--",
            "/bin/true",
        ])
        .output()
        .expect("spawn nono");

    assert!(
        !output.status.success(),
        "non-Policy pack type must be rejected; stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    // load_registry_profile rejection (profile/mod.rs:2322-2330) emits:
    //   "'mock-ns/mock-pack' is a agent pack — only policy packs can be used with --profile."
    // OR signature verification fires first and we see:
    //   "signature/verification failed ..."
    // EITHER is acceptable — the LOCKED requirement is fail-closed rejection.
    let lower = stderr.to_lowercase();
    let pack_type_rejected = lower.contains("agent pack")
        || (lower.contains("policy") && lower.contains("pack"));
    let signature_rejected =
        lower.contains("signature") || lower.contains("verif") || lower.contains("digest");
    assert!(
        pack_type_rejected || signature_rejected,
        "expected pack-type or signature rejection; got: {stderr}"
    );
}
