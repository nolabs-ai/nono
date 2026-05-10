//! Negative-path proofs that the lint scripts actually catch violations.
//!
//! `tests/alias_inventory.rs` and `tests/lint_docs.rs` only prove the
//! current tree passes — a script that always exits 0 would pass them
//! too. These tests prepare a temporary git-shaped workspace containing
//! a deliberate violation and assert the script rejects it (exit non-zero
//! with the expected diagnostic).

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .unwrap_or(manifest_dir)
}

/// Initialise a temp dir as a git repo so `git rev-parse --show-toplevel`
/// inside the lint scripts resolves to the temp root rather than the real
/// nono repo.
fn init_temp_git_repo(dir: &Path) {
    let out = Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir)
        .output()
        .expect("git init");
    assert!(out.status.success(), "git init failed: {:?}", out);
}

fn run_script(script: &Path, cwd: &Path) -> std::process::Output {
    Command::new("bash")
        .arg(script)
        .current_dir(cwd)
        .output()
        .expect("invoke script")
}

#[test]
fn lint_docs_rejects_quoted_override_deny_outside_allowlist() {
    let root = repo_root();
    let script = root.join("scripts").join("lint-docs.sh");
    assert!(script.exists(), "lint-docs.sh missing");

    let tmp = tempfile::tempdir().expect("tempdir");
    init_temp_git_repo(tmp.path());

    // Create a file in `crates/` (in scope) with the JSON-quoted form of
    // a legacy-only key. The previous regex (dotted form only) would
    // miss this — the post-fix script must reject it. Use a .json file
    // so the bytes on disk are real JSON, not Rust-escaped string
    // literals (which would put backslashes between the quotes and the
    // key, defeating the regex).
    let target_dir = tmp.path().join("crates").join("dummy");
    std::fs::create_dir_all(&target_dir).expect("mkdir");
    let target_file = target_dir.join("offender.json");
    let mut content = String::from("{\n  ");
    content.push('"');
    content.push_str("override_deny");
    content.push('"');
    content.push_str(": []\n}\n");
    std::fs::write(&target_file, content).expect("write");

    let out = run_script(&script, tmp.path());
    assert!(
        !out.status.success(),
        "lint-docs.sh should reject the quoted legacy form; \
         stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("forbidden") || combined.contains("override_deny"),
        "expected diagnostic about the violation; got: {combined}"
    );
}

#[test]
fn lint_docs_accepts_clean_tree() {
    // Sanity check the negative-path harness itself: an empty git repo
    // (no `crates/`, `docs/`, etc.) has no forbidden tokens and the
    // script must exit 0.
    let root = repo_root();
    let script = root.join("scripts").join("lint-docs.sh");
    let tmp = tempfile::tempdir().expect("tempdir");
    init_temp_git_repo(tmp.path());

    let out = run_script(&script, tmp.path());
    assert!(
        out.status.success(),
        "lint-docs.sh should accept a clean tree; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn alias_inventory_rejects_naked_serde_alias() {
    let root = repo_root();
    let script = root.join("scripts").join("test-list-aliases.sh");
    assert!(script.exists(), "test-list-aliases.sh missing");

    let tmp = tempfile::tempdir().expect("tempdir");
    init_temp_git_repo(tmp.path());

    // Create a `crates/` file containing a `#[serde(alias = ...)]` with
    // NO `/// ALIAS(...)` marker on the line above. The script must
    // reject it.
    let target_dir = tmp.path().join("crates").join("dummy").join("src");
    std::fs::create_dir_all(&target_dir).expect("mkdir");
    std::fs::write(
        target_dir.join("lib.rs"),
        r#"// Naked alias — no /// ALIAS marker above.
#[derive(serde::Deserialize)]
pub struct Bad {
    #[serde(alias = "old_name")]
    pub new_name: String,
}
"#,
    )
    .expect("write");

    let out = run_script(&script, tmp.path());
    assert!(
        !out.status.success(),
        "test-list-aliases.sh should reject a naked alias; \
         stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("MISSING") || combined.contains("ALIAS"),
        "expected diagnostic about the missing marker; got: {combined}"
    );
}

#[test]
fn alias_inventory_rejects_marker_missing_field() {
    let root = repo_root();
    let script = root.join("scripts").join("test-list-aliases.sh");

    let tmp = tempfile::tempdir().expect("tempdir");
    init_temp_git_repo(tmp.path());

    // Marker is present but missing the `issue` field — script must
    // catch this.
    let target_dir = tmp.path().join("crates").join("dummy").join("src");
    std::fs::create_dir_all(&target_dir).expect("mkdir");
    std::fs::write(
        target_dir.join("lib.rs"),
        r#"
#[derive(serde::Deserialize)]
pub struct Bad {
    /// ALIAS(canonical="new_name", introduced="v0.41.0", remove_by="v1.0.0")
    #[serde(alias = "old_name")]
    pub new_name: String,
}
"#,
    )
    .expect("write");

    let out = run_script(&script, tmp.path());
    assert!(
        !out.status.success(),
        "test-list-aliases.sh should reject a marker missing the 'issue' \
         field; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn alias_inventory_rejects_unapproved_deprecated_module_reach_in() {
    // The fully-qualified path access pattern (no `use` statement) used
    // to bypass the script's `use crate::deprecated_*` check. The
    // post-fix script must catch
    // `crate::deprecated_schema::WarningCounterGuard::begin()` as well.
    let root = repo_root();
    let script = root.join("scripts").join("test-list-aliases.sh");

    let tmp = tempfile::tempdir().expect("tempdir");
    init_temp_git_repo(tmp.path());

    // First add a "deprecated_schema.rs" file so the path pattern is
    // realistic — the script greps for `crate::deprecated_(schema|policy)::`
    // anywhere it's used. Place the offending caller in a non-approved
    // file (anything that's not main.rs / app_runtime.rs / cli.rs /
    // profile/mod.rs).
    let src = tmp.path().join("crates").join("dummy").join("src");
    std::fs::create_dir_all(&src).expect("mkdir");
    std::fs::write(
        src.join("deprecated_schema.rs"),
        "// pretend deprecated module\n",
    )
    .expect("write");
    std::fs::write(
        src.join("rogue_caller.rs"),
        "fn x() { let _g = crate::deprecated_schema::WarningCounterGuard::begin(); }\n",
    )
    .expect("write");

    let out = run_script(&script, tmp.path());
    assert!(
        !out.status.success(),
        "test-list-aliases.sh should reject the fully-qualified \
         crate::deprecated_schema:: reach-in from a non-approved file; \
         stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        combined.contains("UNAPPROVED"),
        "expected UNAPPROVED diagnostic; got: {combined}"
    );
}
