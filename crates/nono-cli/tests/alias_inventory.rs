//! Integration test that exercises `scripts/test-list-aliases.sh`.
//!
//! The script enforces the `/// ALIAS(canonical=..., introduced=...,
//! remove_by=..., issue=...)` marker convention across the workspace. Running
//! it from `cargo test` ensures CI fails if any new `#[serde(alias = ...)]` or
//! `#[arg(..., alias = ...)]` attribute is introduced without a marker.
//!
//! See `docs/plans/2026-04-24-issue-594-phase-2-schema-plan.md`, Part F.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at crates/nono-cli; walk up two levels.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .unwrap_or(manifest_dir)
}

#[test]
fn alias_inventory_script_passes() {
    let root = repo_root();
    let script = root.join("scripts").join("test-list-aliases.sh");
    assert!(
        script.exists(),
        "missing script: {} — Part F1 is incomplete",
        script.display()
    );

    let output = Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        .output()
        .expect("failed to invoke test-list-aliases.sh");

    if !output.status.success() {
        panic!(
            "test-list-aliases.sh failed (exit {:?}).\n\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
