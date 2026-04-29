---
phase: 28-authenticode-chain-walker-subject-extraction
created: 2026-04-29
type: phase-context
---

# Phase 28 Context — Authenticode Chain-Walker Subject Extraction

## Override of plan's Task 7 PATH-3 recommendation → PATH-4

The plan at `28-01-AUDC-PLAN.md` Task 7 (lines ~1140-1230) presents a fork between PATH-1 (lib+bin refactor of nono-cli to expose `query_authenticode_status` to integration tests), PATH-2 (subprocess invocation pattern), and PATH-3 (keep `#[ignore]` with v2.4-deferred message). The plan recommends PATH-3 for "single-plan-phase scope preservation."

**This CONTEXT overrides the plan's recommendation.** Task 7 must take **PATH-4** (not enumerated in the plan): **move** the deferred test `authenticode_signed_records_subject` from `crates/nono-cli/tests/exec_identity_windows.rs` (integration test file, lines 60-75) to `crates/nono-cli/src/exec_identity_windows.rs::tests` (unit-test module, where Task 6 already adds new tests). Re-enable the test (remove `#[ignore]`) at the new inline location.

### Why PATH-4 over PATH-3

The PATH-3 recommendation effectively re-defers REQ-AUDC-02 acceptance #1 ("Test runs (no `#[ignore]`) and passes against a fixture signed binary") to a hypothetical Plan 28-02. v2.3 has already absorbed one partial close (Phase 27 Path B) due to Windows-host harness blockers; absorbing a second one (Phase 28 PATH-3) would compound the milestone's "partial close" debt without strong technical justification.

PATH-4 is technically clean:

- The deferred test's intended assertions (per its own commented body at `tests/exec_identity_windows.rs:65-69`) are *substantively identical* to Task 6's new unit test `signed_system_binary_extracts_cn_subject` — both query `notepad.exe`, both expect `AuthenticodeStatus::Valid { signer_subject, .. }`, both assert `signer_subject.to_lowercase().contains("microsoft")`.
- The test's comment at `tests/exec_identity_windows.rs:32-38` admits the integration-boundary import is fragile and would need updating "if a future restructure converts nono-cli into a `lib.rs` + `bin/main.rs` split." That admission acknowledges the test was always going to need relocation; PATH-4 just resolves it now without the lib+bin refactor.
- Moving the test inline preserves its name (`authenticode_signed_records_subject`), preserves its substring-match semantics, and lets it run as part of `cargo test -p nono-cli --bin nono` alongside the other unit tests.
- No lib+bin refactor required (avoids PATH-1's out-of-scope risk).
- No subprocess invocation needed (avoids PATH-2's `dirs::home_dir()` USERPROFILE blocker that bit Phase 27).

### Concrete PATH-4 instructions for the executor

**Task 7 deliverable shape (overrides the plan's PATH-3 spec at lines 1209-1234):**

1. **Delete** `crates/nono-cli/tests/exec_identity_windows.rs::authenticode_signed_records_subject` function body + `#[ignore]` attribute + the `panic!()` placeholder (lines ~60-75 of the integration test file).
2. **Add** the test inline in `crates/nono-cli/src/exec_identity_windows.rs::tests` module (sibling to the new Task 6 tests). Use the same name (`authenticode_signed_records_subject`) and the substantive assertion shape:

   ```rust
   /// REQ-AUDC-02 acceptance #1 (re-enabled in Phase 28 Plan 28-01 from
   /// the v2.2 Plan 22-05b deferral). Substring-matches a known-signed
   /// Windows-shipped binary's signer subject.
   #[test]
   fn authenticode_signed_records_subject() {
       let path = std::path::Path::new(r"C:\Windows\System32\notepad.exe");
       if !path.exists() {
           // Graceful skip on hosts where the fixture is missing
           // (e.g., Windows Nano server, ARM64 dev images).
           return;
       }
       let status = query_authenticode_status(path)
           .expect("query_authenticode_status against signed system binary should succeed");
       match status {
           AuthenticodeStatus::Valid { signer_subject, .. } => {
               assert!(
                   signer_subject.to_lowercase().contains("microsoft"),
                   "expected signer subject to contain 'microsoft'; got: {signer_subject}",
               );
           }
           other => panic!("expected Valid status; got {other:?}"),
       }
   }
   ```

3. **Update the integration test file's preamble** (`crates/nono-cli/tests/exec_identity_windows.rs` lines 1-38) to remove the stale comment block referring to the now-relocated test. Replace with a short note pointing at the new inline location. Optionally: if the integration test file is now empty after the move (the only other test was `nono_binary_loads_without_unresolved_authenticode_symbols`), keep the file as-is with that one remaining test. Do NOT delete the integration test file — the linkage probe at line 84 still has value.

### Verification gate adjustment

The plan's Task 8 verification gate item that says "deferred `authenticode_signed_records_subject` test re-enabled" should now read:

```
grep -c '#\[ignore' crates/nono-cli/tests/exec_identity_windows.rs   # returns 0 (was 1)
grep -c 'fn authenticode_signed_records_subject' crates/nono-cli/src/exec_identity_windows.rs   # returns 1 (was 0; relocated from tests/)
cargo test -p nono-cli --bin nono authenticode_signed_records_subject   # exits 0
```

Plus the original verification gate items remain (cargo build, clippy, fmt, full test suite, etc.).

## Other open questions resolved at scope-time

### Q: NonoError variant choice (Task 2)

**Resolution: reuse `NonoError::AuditIntegrity`.** Adding a new `NonoError::AuthenticodeChainWalk { hresult, hint }` variant is Rule-3-deviation overhead for marginal gain — chain-walk failure during `query_authenticode_status` is structurally part of the audit-integrity flow (the Authenticode discriminant is a field on `executable_identity` which is part of `SessionMetadata.audit_integrity`). The hresult + hint can ride in `AuditIntegrity`'s existing message field as a structured prefix like `"authenticode chain-walk failed (hresult=0x{:x}): {hint}"`.

This matches the v2.2 Phase 22-05b posture for similar Windows-API failures and avoids a Rule-4 NonoError surface change.

### Q: WTHelper module path (Task 3)

The plan's `<interfaces>` note (line 136) lists two candidate paths and recommends `Win32::Security::WinTrust::WTHelper*` if both resolve. **Confirmed:** in `windows-sys 0.59`, the `WTHelper*` exports live under `Win32::Security::WinTrust` (the existing import path used for `WinVerifyTrust`). Adding the `Win32_Security_Cryptography_Catalog` + `_Sip` features unlocks `CRYPT_PROVIDER_DATA` / `CRYPT_PROVIDER_SGNR` *type* visibility, not the function exports themselves — those have been in `WinTrust` since 0.52+.

The executor still needs to verify with `cargo check` after adding the features; if `unresolved import` surfaces on `WTHelperGetProvSignerFromChain`, fall back to the alternate path documented in the plan.

## Cross-plan invariants

- **D-21 Windows-invariance:** all Phase 28 source code is `#[cfg(target_os = "windows")]`-gated; non-Windows builds must remain byte-identical. Verify with `cargo check --target x86_64-unknown-linux-gnu` after each task.
- **D-19 cross-phase byte-identical preservation:** `crates/nono/` is untouched in Phase 28. Verify with `git diff --stat HEAD~N HEAD -- crates/nono/` returning empty across all task commits.
- **No `unwrap()` policy:** all new chain-walker code uses `Result` propagation per CLAUDE.md § Error Handling. `unsafe` blocks have `// SAFETY:` comments.
