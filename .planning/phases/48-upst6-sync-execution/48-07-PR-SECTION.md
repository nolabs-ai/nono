---
plan_id: 48-07
cluster: C8
wave: 2
upstream_sha_range: 57005737..530306ee
upstream_commit_count: 2
upstream_tag: v0.55.0
disposition: will-sync
d_48_d2_verdict: no_gap_coverage_present
fork_side_regression_commits: 0
fork_adaptation_commits: 1
---

# Plan 48-07 PR Section: Proxy Credential Format (Cluster C8)

## Summary

Cherry-picks Cluster C8 (2 commits): makes `credential_format` an `Option<String>` so
callers can omit it and get a header-name-aware default (`Authorization` → `Bearer {}`;
other headers → bare `{}`), or supply an explicit format used as-is. Wave 2 plan;
surface-disjoint from C5/C6/C7/C9.

## Upstream commits absorbed

| # | Upstream SHA | Subject | Tag |
|---|-------------|---------|-----|
| C8-01 | `57005737` | `fix(proxy): honor explicit credential_format on custom inject headers` | v0.55.0 |
| C8-02 | `530306ee` | `review fix` (credential_format doc + case-insensitive Authorization test) | v0.55.0 |

Cherry-pick order follows upstream chronological order.

## D-48-D2 Pre-flight Verdict

**`no_gap_coverage_present`** — the cherry-picks themselves add unit tests in
`crates/nono-proxy/src/config.rs` and `crates/nono-proxy/src/credential.rs` exercising
all 3 cases:

- **Case A (omitted → default):** `test_route_config_omitted_format_*`, `test_load_non_authorization_header_omitted_format_injects_bare_secret`
- **Case B (explicit `Bearer {}`):** `test_route_config_explicit_bearer_on_custom_header_preserved`, `test_load_non_authorization_header_explicit_bearer_format`
- **Case C (explicit bare token):** `test_resolved_credential_format_*`, `test_resolved_credential_format_authorization_case_insensitive`

No fork-side regression commit added (Task 2 skipped).

## Fork adaptations

**C8-01 (`57005737`):**

1. `validate_proxy_override` function and its call removed from `profile/mod.rs`. Upstream's function references `cred.proxy` (type `ProxyInjectConfig`) not present in fork's `CustomCredentialDef`. Added fork divergence comment; deferred to future plan porting `ProxyInjectConfig`.

2. `oauth2_cred_builder()` test helper in `profile/mod.rs`: removed `proxy: None`, `tls_client_cert: None`, `tls_client_key: None` fields not in fork's struct.

3. Existing fork tests in `profile/mod.rs`: updated `credential_format: "Bearer {}".to_string()` → `credential_format: Some("Bearer {}".to_string())` (type changed from `String` to `Option<String>`).

4. `credential.rs` tests: adapted to fork's 1-arg `CredentialStore::load(&routes)` (upstream uses 2-arg `load(&routes, &tls)`).

**C8-02 (`530306ee`):** Applied cleanly with auto-merge (doc/comment updates + 1 new test). No fork adaptations required.

**Rule 1 auto-fix (commit `5aef2f04`):** Removed fork-incompatible upstream tests accepted during cherry-pick conflict resolution. Tests used APIs not present in the fork: mTLS config fields (`tls_client_cert/key`), TLS intercept (`intercept_ca_path/dir`), `RouteStore::lookup_by_upstream/lookup_all_by_upstream/has_intercept_route`, `LoadedRoute::requires_intercept/requires_managed_credential`, `build_tls_connector` 4-arg API, `NetworkAuditAuthMechanism/NetworkAuditInjectionMode`. Added inline `TestEnvGuard` to credential.rs tests (nono-cli's `ENV_LOCK`/`EnvVarGuard` not available in nono-proxy).

## Key decisions

- D-48-D2 verdict: `no_gap_coverage_present` — upstream cherry-picks contain sufficient coverage; no fork-side regression test added.
- `validate_proxy_override` dropped — fork divergence documented; deferred to future plan.
- Windows invariant D-48-E1 HONORED: 0 files in exec_strategy_windows/ or nono-shell-broker/ touched.
- 1830 tests pass; 1 pre-existing failure (`audit_verify_reports_signed_attestation_with_pinned_public_key` — Class-B CI debt).

## Files modified

- `crates/nono-cli/data/nono-profile.schema.json` — C8-01, C8-02 (credential_format oneOf schema)
- `crates/nono-cli/src/network_policy.rs` — C8-01, C8-02 (CredentialDef field + doc)
- `crates/nono-cli/src/profile/mod.rs` — C8-01, C8-02 (CustomCredentialDef field, validate_header_mode, doc)
- `crates/nono-cli/src/profile_cmd.rs` — C8-01 (Option<String> usage)
- `crates/nono-proxy/src/config.rs` — C8-01, C8-02 (RouteConfig field, resolved_credential_format(), tests)
- `crates/nono-proxy/src/credential.rs` — C8-01, Rule-1-fix (CredentialStore::load logic, tests)
- `crates/nono-proxy/src/route.rs` — C8-01, Rule-1-fix (RouteConfig in tests)
- `crates/nono-proxy/src/server.rs` — C8-01, Rule-1-fix (RouteConfig in tests, anthropic regression test)
