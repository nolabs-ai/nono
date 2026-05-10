#![cfg(target_os = "windows")]
#![allow(clippy::unwrap_used)]
//! Phase 32 Plan 04 (D-32-11..14): broker.exe Authenticode self-trust-anchor
//! verification at every dispatch.
//!
//! Wave 0 scaffold — body filled in by Plan 04 (32-04-PLAN.md). Tests are
//! Windows-only and use the Phase 31 release-pipeline-built broker artifact
//! at `target/<triple>/release/nono-shell-broker.exe` with SKIP-when-missing.

#[test]
#[ignore = "Wave 0 scaffold — Plan 04 (D-32-13) implements"]
fn self_authenticode_extracts_subject_and_thumbprint() {}

#[test]
#[ignore = "Wave 0 scaffold — Plan 04 (D-32-13) implements"]
fn broker_valid_signature_spawns() {}

#[test]
#[ignore = "Wave 0 scaffold — Plan 04 (D-32-12) implements"]
fn broker_signature_mismatch_refuses_spawn() {}

#[test]
#[ignore = "Wave 0 scaffold — Plan 04 (D-32-12) implements"]
fn broker_unsigned_release_refuses_spawn() {}

#[test]
#[ignore = "Wave 0 scaffold — Plan 04 (D-32-12) implements"]
fn dev_skip_does_not_bypass_release_layout() {}

#[test]
#[ignore = "Wave 0 scaffold — Plan 04 (D-32-14) implements"]
fn each_dispatch_revalidates() {}
