//! Negative-path proofs that the lint scripts actually catch violations.
//!
//! `tests/lint_docs.rs` only proves the current tree passes — a script
//! that always exits 0 would pass it too. These tests prepare a
//! temporary git-shaped workspace containing a deliberate violation and
//! assert the script rejects it (exit non-zero with the expected
//! diagnostic).

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
