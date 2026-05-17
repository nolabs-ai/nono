---
title: "Windows Regression: windows_run_redirects_temp_vars_into_writable_allowlist sibling env_vars flake"
created: 2026-05-16
source: CI run 25973911653 job 76350640289 (Windows Regression)
target_milestone: v2.5
priority: medium
resolves_phase: 42
parent_plan: 41-10
---

# Class E.2: Windows Regression env_vars sibling flake

## Context

CI run 25973911653, job `Windows Regression` (databaseId 76350640289), failed at:

```
test windows_run_redirects_temp_vars_into_writable_allowlist ... FAILED
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 73 filtered out
```

## Root cause

Sibling of Class E.1 — same parallel-test env_vars flake root cause. The `temp_vars` test mutates TMP/TEMP env vars in parallel with other tests that read them, causing intermittent failures.

## Status

- Same disposition as Class E.1: HUMAN-UAT #4 canonical tracking; deferred to v2.5 for structural fix.
- See `.planning/todos/pending/41-10-windows-integration-env-vars-flake.md` for shared remediation plan.

## Suggested fix

Co-fix with Class E.1 via cargo-nextest subprocess-per-test isolation in v2.5.
