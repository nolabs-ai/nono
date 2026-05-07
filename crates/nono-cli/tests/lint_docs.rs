//! Integration test that exercises `scripts/lint-docs.sh`.
//!
//! The script forbids legacy issue #594 schema tokens (`policy.add_*`,
//! `--override-deny`, the JSON-quoted `"override_deny"` etc.) outside its
//! allowlist. Running it from `cargo test` means a docs-only PR that
//! re-introduces a legacy key surfaces locally on `make test` rather than
//! waiting for `make ci`.
//!
//! Pairs with `tests/alias_inventory.rs` (which gates `/// ALIAS` markers).

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .unwrap_or(manifest_dir)
}

#[test]
fn lint_docs_script_passes() {
    let root = repo_root();
    let script = root.join("scripts").join("lint-docs.sh");
    assert!(
        script.exists(),
        "missing script: {} — Part F4 is incomplete",
        script.display()
    );

    let output = Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        .output()
        .expect("failed to invoke lint-docs.sh");

    if !output.status.success() {
        panic!(
            "lint-docs.sh failed (exit {:?}).\n\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}
