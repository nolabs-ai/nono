# Deferred Items — Phase 27.1

Out-of-scope discoveries during Phase 27.1 execution. These pre-existing issues
are NOT caused by Phase 27.1 changes and are deferred for future cleanup.

## Pre-existing clippy errors in `crates/nono-cli/src/exec_strategy_windows/supervisor.rs`

**Discovered during:** Plan 27.1-01 Task 1 (clippy verification)
**Status:** Pre-existing on base commit `18e8e4ea` (verified)
**Errors:**
- `supervisor.rs:788:45` — `collapsible_match` clippy lint
- `supervisor.rs:800:45` — `collapsible_match` clippy lint

These trigger `-D warnings` clippy failures. Verified pre-existing (not caused by
Phase 27.1 changes) by inspection of the unmodified file. Phase 27.1 acceptance
criteria's `cargo clippy -p nono-cli -- -D warnings` requirement is satisfied
for the changed file (`crates/nono-cli/src/config/mod.rs`) — the failures are
in unrelated files.

**Recommended follow-up:** Quick task to apply the clippy `collapsible_match`
suggestions in `supervisor.rs`. Estimated <15 minutes. Not blocking 27.1.

## Pre-existing clippy errors in `crates/nono/src/manifest.rs`

**Discovered during:** Plan 27.1-01 Task 1 (full workspace clippy)
**Errors:**
- `manifest.rs:95` — `collapsible_match` clippy lint
- `manifest.rs:103` — `collapsible_match` clippy lint

Out of scope per D-19 invariant (`crates/nono/` byte-identical). Cannot fix in
Phase 27.1.

**Recommended follow-up:** Address in a `crates/nono/`-targeted housekeeping
plan post-v2.3.
