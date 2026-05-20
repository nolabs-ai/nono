---
title: "Windows Integration: windows_run_redirects_profile_state_vars_into_writable_allowlist parallel env_vars flake"
created: 2026-05-16
source: CI run 25973911653 job 76350640287 (Windows Integration)
target_milestone: v2.6
priority: medium
resolves_phase: 44
parent_plan: 41-10
---

# Class E.1: Windows Integration env_vars flake

## Context

CI run 25973911653, job `Windows Integration` (databaseId 76350640287), failed at:

```
test windows_run_redirects_profile_state_vars_into_writable_allowlist ... FAILED
```

## Root cause

Already-known parallel-test env_vars flake. Plan 41-05 added `EnvVarGuard::set_all` to mitigate, deferred to HUMAN-UAT #4 for 10x parallel reruns on Windows host. CI runner exhibits the flake intermittently because Cargo runs tests in parallel within the same process and env-var mutations leak between sibling tests.

## Status

- HUMAN-UAT #4 is the canonical tracking item for this class.
- Phase 41 VERIFICATION carries it forward (carry-forward item #4).
- Not a Plan 41-10 in-scope fix - structural test isolation (subprocess-per-test, NEXTEST_SCOPE=test) is the only durable fix, deferred to v2.5 or later.

## Suggested fix (v2.5 / Phase 42)

Switch env-var-mutating tests to `cargo nextest` subprocess-per-test isolation, or refactor the test fixtures so all mutations go through a process-wide single-threaded mutex (already partially done via `crate::test_env::EnvVarGuard`).
