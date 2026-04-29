---
status: complete
phase: 22-upst2-upstream-v038-v040-parity-sync
source: [22-01-PROF-SUMMARY.md, 22-02-POLY-SUMMARY.md, 22-03-PKG-SUMMARY.md, 22-04-OAUTH-SUMMARY.md, 22-05a-AUD-CORE-SUMMARY.md, 22-05b-AUD-RENAME-SUMMARY.md]
started: 2026-04-28T00:00:00Z
updated: 2026-04-29T01:35:00Z
---

## Current Test

[testing complete]

## Tests

### 1. Build Smoke
expected: `cargo build --workspace` exits 0 cleanly (incremental rebuild after the six 22-* plans).
result: pass

### 2. `nono --help` lists `session`, hides `prune`
expected: Top-level `nono --help` shows `session    Manage runtime session storage (cleanup)` in the subcommand list, and does NOT list `prune` in the visible subcommands.
result: pass
note: "Initial fail was stale binary. After rebuild, `nono --help` shows `session` and hides `prune` as expected (2026-04-28)."

### 3. `nono prune` emits stderr deprecation note
expected: `nono prune --dry-run` still runs but writes `warning: \`nono prune\` is deprecated; use \`nono session cleanup\` instead` to stderr on every invocation.
result: pass
note: "Initial fail was stale binary. After rebuild, `.\\nono prune --dry-run` emits `warning: \`nono prune\` is deprecated; use \`nono session cleanup\` instead` on stderr as expected (2026-04-28)."

### 4. `nono session cleanup --dry-run` works
expected: New `nono session cleanup --dry-run` subcommand executes — lists "Would remove" entries (or reports "nothing to remove") and exits 0.
result: pass
note: "After rebuild, `.\\nono session cleanup --dry-run` listed three `Would remove: <hash> (started ...)` entries and exited 0 (2026-04-28)."

### 5. `nono audit cleanup` peer subcommand works
expected: `nono audit cleanup --keep 5 --dry-run` runs and either lists candidate sessions or reports "No audit sessions match"; exits 0.
result: pass
note: "`.\\nono audit cleanup --keep 5 --dry-run` printed `nono No audit sessions match the cleanup filters.` and exited 0 (2026-04-28)."

### 6. `nono audit verify --help` exposes attestation flag
expected: `nono audit verify --help` lists the `--public-key-file <PATH>` flag (AUD-02 attestation verification path).
result: pass
note: "`nono audit verify --help` lists `--public-key-file <PATH>` with the expected description (Plan 22-05a Task 7, upstream `6ecade2e`); embedded-bundle fallback documented (2026-04-28)."

### 7. `nono package` subcommand tree
expected: `nono package --help` lists four subcommands: `pull`, `remove`, `search`, `list`.
result: skipped
reason: "UAT-spec error. Implementation does NOT nest these under a `nono package` parent — Plan 22-03 PKG-01..04 ports upstream's flat top-level shape (`Cmd::Pull` / `Cmd::Remove` / `Cmd::Update` / `Cmd::Search` / `Cmd::List` at cli.rs:887-946; help banner § PACKAGES at cli.rs:222-227). Replaced by Test 7b which verifies the actual shipped shape."

### 7b. `nono pull --help` works (PKG-01..04 flat-subcommand shape)
expected: `nono pull --help` prints the pull subcommand's usage block without "unrecognized subcommand" error and exits 0 (verifies the flat PKG shape upstream uses).
result: pass
note: "`nono pull --help` printed `Install a signed nono pack from the registry` + USAGE + Arguments block; exited 0 (2026-04-28). Verifies cli.rs:887-946 Cmd::Pull/Remove/Update/Search/List dispatch."

### 8. POLY-02 `--rollback` + `--no-audit` mutual exclusion (post CL-01-M)
expected: `nono run --rollback --no-audit -- cmd /c echo hi` is rejected at parse time with a clap conflict error like "the argument '--no-audit' cannot be used with '--rollback'" (or vice-versa for reverse arg order). Exit code is non-zero. Note: spec revised post CL-01-M (commit 27a5ff78) — only `--no-audit` (entire audit trail) conflicts with `--rollback`; `--no-audit-integrity` (cryptographic ledger only) is orthogonal and now permitted with `--rollback`.
result: pass
note: "Output: `error: the argument '--rollback' cannot be used with '--no-audit'` + Usage line; exit code non-zero (2026-04-28). POLY-02 mutex enforced at clap parse time."

### 9. `claude-no-kc` builtin profile loads
expected: `nono policy show claude-no-kc` (positional profile arg) loads the new builtin profile (PROF-04) and prints its resolved capability set without error. Original spec used `--profile <name>` flag shape, which is incorrect — `policy show` takes the profile name as a positional argument.
result: pass
note: "`nono policy show claude-no-kc` printed full resolved set: 31 security groups (incl. deny_keychains_macos), Filesystem allow/allow_file lists with $HOME expansions to C:\\Users\\OMack, ReadWrite workdir, rollback exclusions, open URLs. No error. Confirms PROF-04 builtin landed (2026-04-28)."

### 10. `--audit-integrity` produces chain_head + merkle_root
expected: `nono run --audit-integrity -- cmd /c echo hello` creates a new audit session under `~/.nono/audit/` (or `%USERPROFILE%\.nono\audit\`); the SessionMetadata file contains non-empty `chain_head` and `merkle_root` fields plus an `executable_identity` block (canonical path + SHA-256).
result: pass
note: |
  Session 20260428-213345-27132 produced under %USERPROFILE%\.nono\audit\.
  - executable_identity.resolved_path: \\?\C:\Windows\System32\cmd.exe
  - executable_identity.sha256: 14cc8ab1dcf0d9f19e8fb82deb547cf8c462c56a0e43f7addc02641ab3c81651
  - audit_integrity.hash_algorithm: sha256
  - audit_integrity.event_count: 2
  - audit_integrity.chain_head: c439d7da04e844d98b5c78780256ef991ed7d14f15c87f117eddb59a6fda2933
  - audit_integrity.merkle_root: 92eb48cbc0d0e4371493a72a46c00b9335ed59921270fbc64adce851543ddf20
  - audit_attestation: null (expected — no --audit-sign-key flag)
  - rollback_status: skipped (expected — no --rollback flag)
  Confirms AUD-01 (chain_head + merkle_root commitments), AUD-02 (audit_integrity block shape, attestation slot), AUD-03 (executable_identity SHA-256 portion). Authenticode discriminant deferred to v2.3 backlog per PROJECT plan note (2026-04-28).

## Summary

total: 11
passed: 10
issues: 0
pending: 0
skipped: 1
blocked: 0

## Gaps

[none — test 2/3 stale-binary fails cleared after rebuild re-run]
