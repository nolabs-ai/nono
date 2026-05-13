//! Integration tests for profile-drafts surface (Phase 36.5 D-36.5-A1..A3).
//!
//! Tests `nono profile init --draft`, `--refresh`, `nono profile promote`,
//! and `nono profile validate --draft` as subprocess invocations to ensure:
//!   1. Exit codes are directly observable.
//!   2. File-system side-effects are sandboxed to a TempDir.
//!   3. Cross-process env-var isolation avoids test pollution.
//!
//! Pattern: `Command::env("APPDATA"|"XDG_CONFIG_HOME", dir.path())` to redirect
//! the config dir for the subprocess. Both are passed so the test is cross-platform.

use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn nono_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_nono"))
}

/// Set up config-dir env vars for the subprocess pointing at `dir`.
/// Both APPDATA (Windows) and XDG_CONFIG_HOME (Unix) are set so tests
/// are portable across platforms.
fn with_config_dir<'a>(cmd: &'a mut Command, dir: &Path) -> &'a mut Command {
    cmd.env("APPDATA", dir)
        .env("XDG_CONFIG_HOME", dir)
        .env("HOME", dir)
}

/// Minimal valid profile JSON used as skeleton content for tests.
fn minimal_profile_json(name: &str) -> String {
    format!(
        r#"{{
  "meta": {{ "name": "{name}", "version": "1.0" }},
  "security": {{ "groups": [] }}
}}
"#
    )
}

/// Write a minimal profile JSON to `<dir>/nono/profiles/<name>.json`.
/// Creates parent directories automatically.
fn write_canonical_profile(dir: &Path, name: &str) {
    let profiles_dir = dir.join("nono").join("profiles");
    std::fs::create_dir_all(&profiles_dir).expect("create profiles dir");
    let path = profiles_dir.join(format!("{name}.json"));
    std::fs::write(&path, minimal_profile_json(name)).expect("write canonical profile");
}

/// Write a minimal profile JSON to `<dir>/nono/profile-drafts/<name>.json`.
/// Creates parent directories automatically.
fn write_draft_profile(dir: &Path, name: &str) {
    let drafts_dir = dir.join("nono").join("profile-drafts");
    std::fs::create_dir_all(&drafts_dir).expect("create profile-drafts dir");
    let path = drafts_dir.join(format!("{name}.json"));
    std::fs::write(&path, minimal_profile_json(name)).expect("write draft profile");
}

// ---------------------------------------------------------------------------
// Commit Group 1 tests: init --draft + --refresh
// ---------------------------------------------------------------------------

#[test]
fn init_draft_writes_to_drafts_dir() {
    let dir = TempDir::new().expect("create temp dir");
    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "init", "--draft", "myagent"])
        .output()
        .expect("run nono");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "init --draft should exit 0; stderr: {stderr}"
    );

    // Draft file must exist under profile-drafts/
    let draft_path = dir
        .path()
        .join("nono")
        .join("profile-drafts")
        .join("myagent.json");
    assert!(
        draft_path.exists(),
        "draft file must exist at {}",
        draft_path.display()
    );

    // Canonical file must NOT have been created
    let canonical_path = dir
        .path()
        .join("nono")
        .join("profiles")
        .join("myagent.json");
    assert!(
        !canonical_path.exists(),
        "canonical profile must not exist (was: {})",
        canonical_path.display()
    );
}

#[test]
fn init_draft_with_existing_canonical_writes_base_sidecar() {
    let dir = TempDir::new().expect("create temp dir");
    // Pre-create canonical profile
    write_canonical_profile(dir.path(), "myagent");

    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "init", "--draft", "myagent", "--force"])
        .output()
        .expect("run nono");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "init --draft with existing canonical should exit 0; stderr: {stderr}"
    );

    // Draft JSON must exist
    let draft_path = dir
        .path()
        .join("nono")
        .join("profile-drafts")
        .join("myagent.json");
    assert!(draft_path.exists(), "draft JSON must exist");

    // Sidecar .base must exist (canonical was present)
    let base_path = dir
        .path()
        .join("nono")
        .join("profile-drafts")
        .join("myagent.base");
    assert!(
        base_path.exists(),
        "sidecar .base file must exist when canonical is present"
    );

    // .base content must be 64 hex chars (SHA-256)
    let base_content = std::fs::read_to_string(&base_path).expect("read .base file");
    let base_content = base_content.trim();
    assert_eq!(
        base_content.len(),
        64,
        "base hash must be 64 hex chars, got: {base_content:?}"
    );
    assert!(
        base_content.chars().all(|c| c.is_ascii_hexdigit()),
        "base hash must be lowercase hex, got: {base_content:?}"
    );
}

#[test]
fn init_draft_force_overwrites() {
    let dir = TempDir::new().expect("create temp dir");

    // First init creates the draft
    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "init", "--draft", "myagent"])
        .output()
        .expect("run nono first time");
    assert!(output.status.success(), "first init must succeed");

    // Second init without --force must fail
    let mut cmd2 = nono_bin();
    with_config_dir(&mut cmd2, dir.path());
    let output2 = cmd2
        .args(["profile", "init", "--draft", "myagent"])
        .output()
        .expect("run nono second time");
    assert!(
        !output2.status.success(),
        "second init without --force must fail"
    );
    let stderr2 = String::from_utf8_lossy(&output2.stderr);
    assert!(
        stderr2.contains("already exists") || stderr2.contains("Use --force"),
        "stderr must mention existing file, got: {stderr2}"
    );

    // Second init WITH --force must succeed
    let mut cmd3 = nono_bin();
    with_config_dir(&mut cmd3, dir.path());
    let output3 = cmd3
        .args(["profile", "init", "--draft", "myagent", "--force"])
        .output()
        .expect("run nono with --force");
    let stderr3 = String::from_utf8_lossy(&output3.stderr);
    assert!(
        output3.status.success(),
        "init --draft --force must succeed; stderr: {stderr3}"
    );
}

#[test]
fn init_draft_refresh_preserves_content() {
    let dir = TempDir::new().expect("create temp dir");

    // Pre-create canonical and draft
    write_canonical_profile(dir.path(), "myagent");
    write_draft_profile(dir.path(), "myagent");

    // Write a stale sidecar manually
    let base_path = dir
        .path()
        .join("nono")
        .join("profile-drafts")
        .join("myagent.base");
    std::fs::write(&base_path, "a".repeat(64)).expect("write stale sidecar");

    let draft_before = std::fs::read_to_string(
        dir.path()
            .join("nono")
            .join("profile-drafts")
            .join("myagent.json"),
    )
    .expect("read draft before");

    // Run --refresh
    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "init", "--draft", "--refresh", "myagent"])
        .output()
        .expect("run nono refresh");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "--refresh should exit 0; stderr: {stderr}"
    );

    // Draft JSON content must be UNCHANGED
    let draft_after = std::fs::read_to_string(
        dir.path()
            .join("nono")
            .join("profile-drafts")
            .join("myagent.json"),
    )
    .expect("read draft after");
    assert_eq!(
        draft_before, draft_after,
        "--refresh must not modify draft JSON content"
    );

    // Sidecar must be updated (not still "aaa...")
    let base_after = std::fs::read_to_string(&base_path).expect("read sidecar after");
    let base_after = base_after.trim();
    assert_ne!(
        base_after,
        "a".repeat(64).as_str(),
        "sidecar must be updated by --refresh"
    );
    assert_eq!(
        base_after.len(),
        64,
        "refreshed sidecar must be 64 hex chars"
    );
}

#[test]
fn init_draft_refresh_errors_without_canonical() {
    let dir = TempDir::new().expect("create temp dir");

    // Only a draft, no canonical
    write_draft_profile(dir.path(), "myagent");

    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "init", "--draft", "--refresh", "myagent"])
        .output()
        .expect("run nono refresh without canonical");

    assert!(
        !output.status.success(),
        "--refresh without canonical must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no canonical profile to refresh against"),
        "stderr must mention missing canonical, got: {stderr}"
    );
}

#[test]
fn init_draft_refresh_errors_without_draft() {
    let dir = TempDir::new().expect("create temp dir");
    // No draft at all

    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "init", "--draft", "--refresh", "myagent"])
        .output()
        .expect("run nono refresh without draft");

    assert!(
        !output.status.success(),
        "--refresh without draft must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no draft to refresh"),
        "stderr must mention missing draft, got: {stderr}"
    );
}

#[test]
fn init_draft_invalid_name_rejected() {
    let dir = TempDir::new().expect("create temp dir");

    let mut cmd = nono_bin();
    with_config_dir(&mut cmd, dir.path());
    let output = cmd
        .args(["profile", "init", "--draft", "../etc/passwd"])
        .output()
        .expect("run nono with invalid name");

    assert!(
        !output.status.success(),
        "invalid profile name must be rejected"
    );
}
