//! Phase 32 Plan 02 (D-32-03): asserts `nono trust verify --keyless` makes
//! ZERO outbound HTTP calls (verify-is-offline invariant).
//!
//! Wave 0 scaffold — body filled in by Plan 02. Uses `httpmock` to spin up
//! mock Fulcio + Rekor servers and asserts neither receives any request
//! during a verify against the frozen fixture cache.

#[test]
#[ignore = "Wave 0 scaffold — Plan 02 (D-32-03) implements"]
fn verify_makes_no_outbound_http_calls() {
    // Plan 02 fills in
}
