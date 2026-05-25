---
plan_id: 48-07
plan_name: PROXY-CRED-FORMAT
phase: 48
phase_name: upst6-sync-execution
cluster: C8
cluster_disposition: will-sync
upstream_sha_range: 57005737..530306ee
upstream_commit_count: 2
baseline_sha: 3f638dc6
d_48_d2_verdict: no_gap_coverage_present
fork_side_regression_commits: 0
fork_adaptation_commits: 1
lane_transitions: "deferred to live CI; no local green→red transitions from C8"
skipped_gates_environmental: [3, 6, 7, 8, 9]
skipped_gates_preexisting_debt: [1, 2, 4]
pr_section: 48-07-PR-SECTION.md
status: complete
completed: "2026-05-25"
duration_minutes: 120
tasks_completed: 6
files_modified: 11
requirements: [REQ-UPST6-02]
tags: [upstream-sync, cherry-pick, proxy, credential, schema, wave-2]

dependency_graph:
  requires: [48-02, 48-03]
  provides: [C8-proxy-cred-format]
  affects:
    - crates/nono-cli/data/nono-profile.schema.json
    - crates/nono-cli/src/network_policy.rs
    - crates/nono-cli/src/profile/mod.rs
    - crates/nono-cli/src/profile_cmd.rs
    - crates/nono-proxy/src/config.rs
    - crates/nono-proxy/src/credential.rs
    - crates/nono-proxy/src/route.rs
    - crates/nono-proxy/src/server.rs

tech_stack:
  patterns:
    - "credential_format: Option<String> with #[serde(default)] (None = header-aware default)"
    - "resolved_credential_format(inject_header, credential_format) — case-insensitive Authorization matching"
    - "RouteConfig.credential_format: String → Option<String> across proxy + CLI profile layers"
    - "Schema: credential_format oneOf [{type: string}, {type: null}]"

key_files:
  modified:
    - crates/nono-cli/data/nono-profile.schema.json
    - crates/nono-cli/src/network_policy.rs
    - crates/nono-cli/src/profile/mod.rs
    - crates/nono-cli/src/profile_cmd.rs
    - crates/nono-proxy/src/config.rs
    - crates/nono-proxy/src/credential.rs
    - crates/nono-proxy/src/route.rs
    - crates/nono-proxy/src/server.rs
  created:
    - .planning/phases/48-upst6-sync-execution/48-07-CLOSE-GATE.md
    - .planning/phases/48-upst6-sync-execution/48-07-PR-SECTION.md

decisions:
  - "D-48-D2 verdict: no_gap_coverage_present — upstream cherry-picks contain unit tests in config.rs and credential.rs covering all 3 credential_format cases (A: omitted→default, B: explicit Bearer {}, C: explicit bare token). No fork-side regression commit added."
  - "validate_proxy_override removed (fork's CustomCredentialDef lacks proxy: Option<ProxyInjectConfig>; deferred to future plan porting ProxyInjectConfig)"
  - "Fork-incompatible upstream tests removed from route.rs, server.rs, credential.rs (Rule 1 auto-fix): tests used proxy/tls_client_cert/tls_client_key RouteConfig fields, build_tls_connector 4-arg API, ProxyHandle::intercept_ca_path(), ProxyConfig::intercept_ca_dir, RouteStore methods not in fork"
  - "TestEnvGuard inline struct added to credential.rs tests (ENV_LOCK/EnvVarGuard from nono-cli not available in nono-proxy)"
  - "resolved_credential_format() uses eq_ignore_ascii_case for Authorization case-insensitive matching (C8-02)"
  - "pre-existing macOS clippy errors (Class-B CI debt) not introduced by C8"
---

# Phase 48 Plan 07: PROXY-CRED-FORMAT Summary

**One-liner:** 2 upstream cherry-picks changing credential_format from required String to Option<String> with header-name-aware default resolution via resolved_credential_format() (Cluster C8, Wave 2).

## Objective

Cherry-pick Phase 47 ledger Cluster C8 (proxy credential format on custom inject headers; 2 commits in v0.55.0) onto fork `main`. Makes `credential_format` optional — when omitted, `Authorization` headers get `Bearer {}` and other headers get `{}` (bare secret), with case-insensitive Authorization matching.

## Execution Context

Sequential Wave 2 executor on macOS host (`/Users/oscarmack/nono/.claude/worktrees/agent-ac1845f9e0af6d80b`). Worktree branched off Wave 0 head (`b6702b06`, which includes Plan 48-06 C7 merge).

Wave 1 prerequisite confirmed: Plans 48-02 (PROFILE-SHADOWING) and 48-03 (STARTUP-TIMEOUT) SUMMARY files present, both status: complete/shipped.

## D-48-D2 Pre-flight Inspection (Task 1)

| Check | Result |
|-------|--------|
| Wave 1 plans (48-02, 48-03) closed | CONFIRMED — SUMMARY files present |
| 2 C8 SHAs resolvable in worktree | CONFIRMED (57005737, 530306ee) |
| grep coverage in crates/nono-cli/tests/ + tests/integration/ | 0 lines (no tests reference credential_format in those dirs) |
| Coverage in upstream cherry-pick unit tests themselves | PRESENT — config.rs and credential.rs add mod tests |
| D-48-D2 verdict | no_gap_coverage_present |

**Case coverage in upstream cherry-pick unit tests:**
- Case A (omitted→default): `test_route_config_omitted_format_*` in config.rs; `test_load_non_authorization_header_omitted_format_injects_bare_secret` in credential.rs
- Case B (explicit Bearer {}): `test_route_config_explicit_bearer_on_custom_header_preserved` in config.rs; `test_load_non_authorization_header_explicit_bearer_format` in credential.rs
- Case C (bare token): `test_resolved_credential_format_*` tests in config.rs

No fork-side regression commit added. Task 2 skipped.

## Cherry-pick Manifest (Cluster C8)

| # | Upstream SHA | Fork SHA | Subject |
|---|-------------|----------|---------|
| 1 | `57005737` | `d6c06b6b` | fix(proxy): honor explicit credential_format on custom inject headers |
| 2 | `530306ee` | `1e99fe0f` | review fix — improve credential_format doc + case-insensitive Authorization test |

Both tagged v0.55.0. DCO sign-off + verbatim 7-line D-19 trailers + Co-Authored-By on both.

## Fork Adaptation (Rule 1 Auto-fix)

**Commit `5aef2f04`:** Removed fork-incompatible upstream tests from nono-proxy (808 lines removed).

Upstream cherry-picks accepted test code referencing fields and methods not present in the fork:
- `RouteConfig::proxy`, `RouteConfig::tls_client_cert`, `RouteConfig::tls_client_key` (mTLS config — not ported)
- `ProxyHandle::intercept_ca_path()`, `ProxyConfig::intercept_ca_dir` (TLS intercept — not ported)
- `ProxyHandle::route_diagnostics()` (not in fork)
- `RouteStore::lookup_by_upstream()`, `lookup_all_by_upstream()`, `has_intercept_route()` (not in fork)
- `LoadedRoute::requires_intercept`, `requires_managed_credential`, `managed_auth_mechanism`, `managed_injection_mode` (not in fork)
- `LoadedRoute::missing_managed_credential()` (not in fork)
- `build_tls_connector` 4-arg API (not in fork — only `build_tls_connector_with_ca` exists)
- `NetworkAuditAuthMechanism`, `NetworkAuditInjectionMode` types (not in fork)
- `ENV_LOCK`, `EnvVarGuard` (nono-cli private types — not available in nono-proxy)

Adapted: `TestEnvGuard` inline struct added to credential.rs tests as fork-compatible alternative.

## Profile/mod.rs Fork Divergence

`validate_proxy_override` function and its call removed from `validate_custom_credential` — upstream's function references `cred.proxy` (of type `ProxyInjectConfig`) which does not exist in the fork's `CustomCredentialDef`. Added fork divergence comment. Deferred to a future plan porting `ProxyInjectConfig`.

## Test Results

- `cargo test --workspace`: 1830 passed, 1 pre-existing failure
  - nono library: 680 passed
  - nono-proxy: 40 passed
  - nono-ffi: 16 passed
  - nono-cli unit: 1094 passed
  - nono-cli integration: 6 passed
  - Pre-existing failure: `audit_verify_reports_signed_attestation_with_pinned_public_key` — Class-B CI debt predating C8

## Windows Invariant (D-48-E1)

HONORED — 0 files touched in exec_strategy_windows/ or nono-shell-broker/.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed fork-incompatible upstream tests from nono-proxy**

- **Found during:** Task 3 — cherry-pick conflict resolution accepted too many upstream tests
- **Issue:** C8-01 cherry-pick accepted upstream test code referencing types, fields, and methods not present in the fork (mTLS, TLS intercept, route diagnostics, multi-upstream lookup). Tests compiled in isolation (cargo build --workspace passed) but failed during cargo test --workspace with 20+ E0560/E0599/E0425/E0433 errors.
- **Fix:** Removed 7 categories of fork-incompatible tests across credential.rs, route.rs, server.rs; replaced ENV_LOCK/EnvVarGuard with inline TestEnvGuard in credential.rs; removed proxy/tls_client_cert/tls_client_key from all RouteConfig test literals
- **Files modified:** crates/nono-proxy/src/credential.rs, crates/nono-proxy/src/route.rs, crates/nono-proxy/src/server.rs
- **Commit:** 5aef2f04

## Self-Check: PASSED

All claimed files exist:
- crates/nono-cli/data/nono-profile.schema.json: FOUND (modified)
- crates/nono-cli/src/network_policy.rs: FOUND (modified)
- crates/nono-cli/src/profile/mod.rs: FOUND (modified)
- crates/nono-proxy/src/config.rs: FOUND (modified)
- crates/nono-proxy/src/credential.rs: FOUND (modified)
- .planning/phases/48-upst6-sync-execution/48-07-CLOSE-GATE.md: FOUND
- .planning/phases/48-upst6-sync-execution/48-07-SUMMARY.md: FOUND (this file)

All claimed commits exist:
- d6c06b6b (C8-01 cherry-pick): FOUND
- 1e99fe0f (C8-02 cherry-pick): FOUND
- 5aef2f04 (Rule 1 fix): FOUND
