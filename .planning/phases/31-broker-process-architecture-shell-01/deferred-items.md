# Deferred items - Phase 31

Items discovered during Phase 31 plan execution that are out of scope (pre-existing or unrelated to current task changes).

## Plan 31-01

### Pre-existing clippy `collapsible_match` errors in `crates/nono/src/manifest.rs`

- `crates/nono/src/manifest.rs:95:25` — "this `if` can be collapsed into the outer `match`"
- `crates/nono/src/manifest.rs:103:25` — same lint

These errors fail `cargo clippy -p nono -- -D warnings`. Verified against the
pre-edit working tree (`git stash` + clippy + `git stash pop`); the lints exist
on `90192d05` independent of any Plan 31-01 edits. Out of scope per the
executor `<deviation_rules>` SCOPE BOUNDARY rule. The `nono` crate `cargo build`
is clean — these are clippy-only nags, not compile errors.

### Pre-existing `cargo test -p nono` failures in `trust::bundle::tests`

- `trust::bundle::tests::load_production_trusted_root_succeeds`
- `trust::bundle::tests::verify_bundle_with_invalid_digest`

Verified pre-existing on `90192d05` (the worktree base commit) by running
`cargo test -p nono trust::bundle` against an unstashed working tree before
introducing any Plan 31-01 edits. Out of scope per the SCOPE BOUNDARY rule
— neither test exercises code paths touched by Plan 31-01 (the lifted
`create_low_integrity_primary_token`, the new `BrokerNotFound` variant, or
the harness fix). All four Plan 31-01-introduced tests pass:
3 in `create_low_integrity_primary_token_tests` + 2 in
`broker_not_found_tests`. The 6/6 `pty_token_gate_tests` and 2/2
`low_integrity_primary_token_tests` regression suites also pass.

### Pre-existing `cargo fmt --check` drift in `crates/nono-cli/src/exec_strategy_windows/launch.rs`

Several diffs in the existing `pty_token_gate_tests` module and the
`WindowsTokenArm::WriteRestricted` arm body. Verified via `git stash` +
`cargo fmt --check -p nono-cli` that these diffs predate Plan 31-01. Out of
scope per the SCOPE BOUNDARY rule. Plan 31-01's own edits (the `LowIlPrimary`
arm update, the `_low_integrity_holder: Option<nono::OwnedHandle>` annotation,
and the new `nono::create_low_integrity_primary_token` call) are formatted
correctly. The `nono` crate's added test module and the lifted function were
auto-formatted via `cargo fmt -p nono` before commit.

