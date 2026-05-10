//! REQ-AIPC-NIX-01: structural invariants of the AIPC Unix Futures ADR.
//!
//! Phase 25 Plan 25-02 shipped a decision-only ADR at
//! `docs/architecture/aipc-unix-futures.md`. The plan's must-haves locked five
//! shape invariants that future readers (and supersession decisions) depend on:
//!
//! 1. File exists at the canonical path.
//! 2. Status field is `Accepted` (not `Superseded` / `Deprecated`).
//! 3. Decision table has exactly 6 verdict rows — one per `HandleKind` 0..=5
//!    (File, Socket, Pipe, JobObject, Event, Mutex). Discriminants are pinned
//!    via const assertions in `crates/nono/src/supervisor/aipc_sdk.rs`; if a
//!    HandleKind is renamed or appended, the ADR must follow.
//! 4. Length is in [250, 400] lines (decision-only — not implementation).
//! 5. All six required H2 sections present (Context, Decision Table,
//!    Per-HandleKind Rationale, Alternate Mechanisms, Reversibility,
//!    References).
//!
//! These checks were `bash`-shaped at plan-execution time (Plan 25-02 Task 3
//! verification gates). Lifting them into a Rust integration test gives
//! ongoing CI coverage so a later edit that breaks the contract surfaces at
//! `cargo test` time, not at the next ADR-supersession audit.

use std::path::PathBuf;

fn adr_path() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("..")
        .join("..")
        .join("docs")
        .join("architecture")
        .join("aipc-unix-futures.md")
}

fn read_adr() -> String {
    let path = adr_path();
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("REQ-AIPC-NIX-01: ADR missing at {path:?}: {err}"))
}

#[test]
fn adr_exists_at_locked_path() {
    let path = adr_path();
    assert!(
        path.is_file(),
        "REQ-AIPC-NIX-01: ADR must exist at docs/architecture/aipc-unix-futures.md (resolved {path:?})"
    );
}

#[test]
fn adr_status_is_accepted() {
    let body = read_adr();
    let has_accepted = body
        .lines()
        .any(|line| line.trim() == "**Status:** Accepted");
    assert!(
        has_accepted,
        "REQ-AIPC-NIX-01: ADR must declare `**Status:** Accepted` (a Superseded/Deprecated transition requires updating both the ADR and PROJECT.md cross-link)"
    );
}

#[test]
fn adr_decision_table_has_six_handlekind_rows() {
    let body = read_adr();
    let kinds = ["File", "Socket", "Pipe", "JobObject", "Event", "Mutex"];
    let row_count = kinds
        .iter()
        .filter(|kind| {
            body.lines()
                .any(|line| line.starts_with("| ") && line.contains(&format!("| {kind} |")))
        })
        .count();
    assert_eq!(
        row_count, 6,
        "REQ-AIPC-NIX-01: decision table must have one row per HandleKind 0..=5 (File, Socket, Pipe, JobObject, Event, Mutex). Found {row_count}/6 — discriminants are pinned via aipc_sdk.rs const assertions; if a kind was renamed, update both."
    );
}

#[test]
fn adr_length_is_decision_only_not_implementation() {
    let body = read_adr();
    let lines = body.lines().count();
    assert!(
        (250..=400).contains(&lines),
        "REQ-AIPC-NIX-01: ADR length must be in [250, 400] lines (decision-only, not implementation). Got {lines}. Below 250 = decision under-specified; above 400 = scope creeping into design."
    );
}

#[test]
fn adr_has_all_required_h2_sections() {
    let body = read_adr();
    let required = [
        "## Context",
        "## Decision Table",
        "## Per-HandleKind Rationale",
        "## Alternate Mechanisms",
        "## Reversibility",
        "## References",
    ];
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|heading| !body.lines().any(|line| line.trim() == *heading))
        .collect();
    assert!(
        missing.is_empty(),
        "REQ-AIPC-NIX-01: ADR is missing required H2 sections: {missing:?}. All 6 must be present for the document to function as a decision record."
    );
}

#[test]
fn project_md_cross_links_the_adr() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let project_md = PathBuf::from(manifest_dir)
        .join("..")
        .join("..")
        .join(".planning")
        .join("PROJECT.md");
    let body = std::fs::read_to_string(&project_md).unwrap_or_else(|err| {
        panic!("REQ-AIPC-NIX-01: PROJECT.md missing at {project_md:?}: {err}")
    });
    assert!(
        body.contains("aipc-unix-futures"),
        "REQ-AIPC-NIX-01: PROJECT.md must cross-link the ADR (grep for 'aipc-unix-futures'). Without the back-reference future readers can't navigate from the key-decisions table to the locked verdict."
    );
}
