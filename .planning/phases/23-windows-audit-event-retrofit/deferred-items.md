# Phase 23 Deferred Items

These items were observed during Phase 23 execution but are OUT OF SCOPE per CLAUDE.md
"Avoid `#[allow(dead_code)]`" boundary and the plan's `<scope_guardrails>` ("Phase 23
must not regress, but is not responsible for fixing pre-existing issues").

## Pre-existing clippy errors in `crates/nono/src/manifest.rs`

Two `clippy::collapsible_match` errors at `crates/nono/src/manifest.rs:103` and a sibling
site exist on `main` BEFORE Phase 23. They surface when running:

```
cargo clippy --package nono --lib -- -D warnings -D clippy::unwrap_used
```

Verified pre-existing by stashing Phase 23 changes and re-running clippy: same errors.
Last touched commit on `manifest.rs` predates Phase 22.

## Pre-existing rustfmt drift in `crates/nono-cli/src/audit_attestation.rs`

Three formatting drift hunks (lines 281, 421, 444 region) where rustfmt would prefer a
multi-line tuple-element layout over the current single-line form. Surfaces as a `cargo
fmt --all -- --check` failure. NOT caused by Phase 23 — `cargo fmt --all` on a clean
tree (pre-Phase-23) produces the same diff.

Both items belong to a future cleanup quick task (e.g. "fix pre-existing clippy +
fmt drift on main"). Phase 23 leaves them as-is to keep its commit chain minimal and
focused on REQ-AUD-05.
