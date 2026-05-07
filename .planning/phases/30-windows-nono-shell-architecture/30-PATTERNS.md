# Phase 30: Windows nono shell Interactive Enforcement Architecture - Pattern Map

**Mapped:** 2026-05-07
**Files analyzed:** 9 modify + 2 create + 2 unit-test create-in-place = 13
**Analogs found:** 11 / 13 (2 files genuinely without analog)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality | Wave |
|-------------------|------|-----------|----------------|---------------|------|
| `crates/nono-cli/src/exec_strategy_windows/launch.rs` (cascade arm #6) | production code (token construction) | request-response (token → `CreateProcessAsUserW`) | Same file `launch.rs:1144-1149` (session_sid arm) | **exact** — sibling arm in same cascade | 1 |
| `crates/nono-cli/src/exec_strategy_windows/launch.rs` (`pty_token_gate_tests` mod) | unit test | pure-fn truth-table | Same file `launch.rs:1408-1437` (`detached_token_gate_tests`) | **exact** — same module, same shape | 1 |
| `crates/nono-cli/src/exec_strategy_windows/launch.rs` (`low_integrity_primary_token` test) | unit test | FFI handle property check | `restricted_token.rs:147-198` (`create_restricted_token_with_sid_applies_write_restricted_flag`) | **role-match** — token construction unit test | 1 |
| `scripts/test-windows-shell-write-deny.ps1` | live-shell test harness | request-response (one-shot script into shell, exit-code assertion) | RESEARCH.md § Acceptance #3 Test Pattern (no codebase analog) | **none** — genuinely new pattern; closest sibling is `scripts/windows-test-harness.ps1` (cargo-test orchestrator, NOT live-shell driver) | 1 |
| `scripts/test-windows-shell-tui.ps1` | live-shell test harness (manual) | interactive TUI verification | None in codebase; runbook-style | **none** — genuinely new pattern | 1 |
| `.planning/PROJECT.md` (SHELL-01 row) | bookkeeping | text replacement | Same file lines 60-100 (validated-row pattern) | **exact** — adjacent rows | 1 (first task + last task) |
| `.planning/STATE.md` (key-decisions block + Stopped At) | bookkeeping | text replacement | Same file lines 91-103 (v2.2 / v2.1 key-decisions blocks) | **exact** — same block structure | 1 (last task) |
| `docs/cli/development/windows-poc-handoff.mdx` (security-envelope paragraph) | docs | text insertion | Same file lines 10-17 (top-of-doc `<Note>` block) + `.planning/debug/resolved/windows-supervised-exec-cascade.md:239-243` (Phase 15 waiver wording) | **role-match** — Phase 15 detached waiver text shape | 1 (last task) |
| `.planning/debug/nono-shell-status-dll-init-failed.md` (status flip) | bookkeeping | frontmatter edit | `.planning/debug/resolved/windows-supervised-exec-cascade.md` frontmatter | **exact** — debug-session resolution metadata | 1 (intermediate) + Wave 1 close (move to `resolved/`) |
| `.planning/phases/30-windows-nono-shell-architecture/30-FIELD-SMOKE.md` (optional, planner discretion) | docs / runbook | none | RESEARCH.md § Acceptance #3 Test Pattern + Phase 15's smoke-gate table at `windows-supervised-exec-cascade.md:120-130` | **partial** — runbook checklist | 1 (planner discretion) |
| ProcMon trace files / analysis notes (Wave 2 only) | docs | none | RESEARCH.md § ProcMon Trace Plan (no codebase analog) | **none** | 2 (conditional) |
| `crates/nono-cli/src/supervised_runtime.rs` (Wave 2 conditional fix) | production code | TBD | Same file `supervised_runtime.rs:95-111` (`should_allocate_pty()` gate) | **partial** — same module, hypothetical fix point | 2 (conditional) |
| Cookbook revert (Wave 2 failure path) | docs | text replacement | `docs/cli/development/windows-poc-handoff.mdx:233-239` (existing "Known limitation" section — KEEP) | **exact** — keep that block, strip recommendation | 2 (conditional) |

## Pattern Assignments

### `crates/nono-cli/src/exec_strategy_windows/launch.rs` — new cascade arm #6 (Wave 1, production code, request-response)

**Role:** Token construction for `CreateProcessAsUserW`.
**Data flow:** `pty.is_some()` decision → `create_low_integrity_primary_token()` → raw HANDLE → `CreateProcessAsUserW`.

**Analog:** Same file, the WRITE_RESTRICTED arm at `launch.rs:1144-1149` (the session_sid arm).

**Cascade pattern to mirror** (from `launch.rs:1131-1160`):
```rust
let _restricted_holder: Option<restricted_token::RestrictedToken>;
let _low_integrity_holder: Option<OwnedHandle>;
let is_windows_detached_launch = is_windows_detached_launch();
let h_token: HANDLE = if is_windows_detached_launch {
    _restricted_holder = None;
    _low_integrity_holder = None;
    std::ptr::null_mut()
} else if let Some(ref sid) = config.session_sid {
    let holder = restricted_token::create_restricted_token_with_sid(sid)?;
    let raw = holder.h_token;
    _restricted_holder = Some(holder);
    _low_integrity_holder = None;
    raw
} else if should_use_low_integrity_windows_launch(config.caps) {
    let holder = create_low_integrity_primary_token()?;
    let raw = holder.0;
    _low_integrity_holder = Some(holder);
    _restricted_holder = None;
    raw
} else {
    _restricted_holder = None;
    _low_integrity_holder = None;
    std::ptr::null_mut()
};
// NOTE: do NOT re-wrap h_token in a fresh OwnedHandle — the holder above
// already owns the close. A second wrapper would double-close on Drop.
```

**What to mirror:**
- The two named-local holder bindings (`_restricted_holder`, `_low_integrity_holder`) — already declared at the top of the cascade. The new arm sets `_low_integrity_holder = Some(holder)` and reads `holder.0` once.
- The branch sets the OTHER holder to `None` explicitly (no shadowing).
- The closing comment block ("do NOT re-wrap h_token") stays put — it applies to all arms including the new one.
- `?` propagation on `create_low_integrity_primary_token()` returns a `Result<OwnedHandle>` already.

**What to change:**
- Branch ordering: insert the new arm **between** `is_windows_detached_launch` and `config.session_sid.is_some()`. RESEARCH.md § "Token Cascade Edit Shape" line 92-93 is unambiguous: `pty.is_some()` MUST precede `config.session_sid.is_some()` because `session_sid` is unconditionally `Some(...)` for Windows supervised launches (per `execution_runtime.rs:334`).
- Add a multi-line comment above the new arm citing Phase 30 D-01 + parallel to Phase 15's WRITE_RESTRICTED+DETACHED_PROCESS finding (RESEARCH.md § Wave 1 Code Examples shows the proposed comment text at lines 553-559).

**Wave 1 new arm shape** (RESEARCH.md:548-565, verbatim):
```rust
} else if pty.is_some() {
    // Phase 30 D-01: ConPTY path uses Low-IL primary token (no WRITE_RESTRICTED,
    // no session-SID). WRITE_RESTRICTED + ConPTY triggers STATUS_DLL_INIT_FAILED
    // (0xC0000142) — same class of bug Phase 15 hit on the detached path with
    // DETACHED_PROCESS. Mandatory-label NO_WRITE_UP enforces write-deny because
    // Low-IL subjects do not dominate Medium-IL files (MIC pre-DACL kernel check).
    // Per-session WFP differentiation via FWPM_CONDITION_ALE_USER_ID is waived
    // on this path (falls back to AppID-based filtering, same as Phase 15
    // detached-path waiver). See .planning/phases/30-windows-nono-shell-architecture/30-CONTEXT.md.
    let holder = create_low_integrity_primary_token()?;
    let raw = holder.0;
    _low_integrity_holder = Some(holder);
    _restricted_holder = None;
    raw
}
```

**Pitfalls flagged in RESEARCH.md (must preserve):**
- **Pitfall 1** (OwnedHandle UAF): bind `holder` to a NAMED local. Do not write `let h_token = create_low_integrity_primary_token()?.0;` — the temporary `OwnedHandle` would `Drop` and close the handle before `CreateProcessAsUserW`.
- **Pitfall 5** (double close): the arm-local `holder.0` is the only place the raw HANDLE is read. Do NOT re-wrap in a fresh `OwnedHandle`.

---

### `crates/nono-cli/src/exec_strategy_windows/launch.rs` — `pty_token_gate_tests` module (Wave 1, unit test, pure-fn truth-table)

**Role:** Truth-table unit test for the new `pty.is_some()` gate decision.
**Data flow:** Pure function under env-var lock; assert which cascade arm is selected for each combination.

**Analog:** Same file, `detached_token_gate_tests` at `launch.rs:1408-1437`.

**Pattern to mirror** (verbatim from `launch.rs:1408-1437`):
```rust
#[cfg(test)]
mod detached_token_gate_tests {
    use super::is_windows_detached_launch;
    use crate::test_env::{lock_env, EnvVarGuard};

    #[test]
    fn returns_false_when_env_unset() {
        let _lock = lock_env();
        // Ensure the env var is cleared for the duration of the assertion.
        let g = EnvVarGuard::set_all(&[("NONO_DETACHED_LAUNCH", "1")]);
        g.remove("NONO_DETACHED_LAUNCH");
        assert!(!is_windows_detached_launch());
    }

    #[test]
    fn returns_true_when_env_is_one() {
        let _lock = lock_env();
        let _g = EnvVarGuard::set_all(&[("NONO_DETACHED_LAUNCH", "1")]);
        assert!(is_windows_detached_launch());
    }

    #[test]
    fn returns_false_when_env_is_other_value() {
        let _lock = lock_env();
        let _g = EnvVarGuard::set_all(&[("NONO_DETACHED_LAUNCH", "0")]);
        assert!(!is_windows_detached_launch());
        let _g2 = EnvVarGuard::set_all(&[("NONO_DETACHED_LAUNCH", "true")]);
        assert!(!is_windows_detached_launch());
    }
}
```

**What to mirror:**
- `#[cfg(test)] mod pty_token_gate_tests { ... }` block alongside `detached_token_gate_tests`.
- `lock_env()` + `EnvVarGuard` save/restore (CLAUDE.md mandates env-var save/restore — never bare `std::env::set_var`).
- One `#[test]` per truth-table row.
- Tests assert on a **pure helper** (extract the gate decision into a testable function). RESEARCH.md § "Wave 0 Gaps" line 509 specifies the truth table:
  - `is_detached=false, has_pty=true` → Low-IL primary
  - `is_detached=true, has_pty=true` → null
  - `is_detached=false, has_pty=false, has_session_sid=true` → WRITE_RESTRICTED
  - `is_detached=false, has_pty=false, has_session_sid=false` → null fallback

**What to change:**
- Helper-vs-inline gate: Claude's Discretion per CONTEXT.md D-72 (line 72). If a `should_use_low_il_for_pty(pty, is_detached)` helper is added, the unit tests call it directly. If the gate is inlined, the test extracts it into a hidden `pub(super) fn` for testability.

---

### `crates/nono-cli/src/exec_strategy_windows/launch.rs` — `low_integrity_primary_token_sets_low_il` test (Wave 1, unit test, FFI property check)

**Role:** Verify the duplicated token has integrity SID `S-1-16-4096` (Low).
**Data flow:** Construct token → query `TokenIntegrityLevel` via `GetTokenInformation` → assert last sub-authority is `SECURITY_MANDATORY_LOW_RID`.

**Analog:** `crates/nono-cli/src/exec_strategy_windows/restricted_token.rs:147-198` (`create_restricted_token_with_sid_applies_write_restricted_flag`).

**Pattern to mirror** (`restricted_token.rs:123-198`):
```rust
#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenRestrictedSids, TOKEN_GROUPS};

    /// Regression test for the cascading `nono run --allow-cwd` failures...
    #[test]
    fn create_restricted_token_with_sid_applies_write_restricted_flag() {
        let sid = generate_session_sid();
        let token = create_restricted_token_with_sid(&sid)
            .expect("create_restricted_token_with_sid must succeed for a freshly-generated SID");
        assert!(
            !token.h_token.is_null(),
            "restricted token handle is non-null"
        );

        // Query TokenRestrictedSids — first call probes required size.
        let mut needed: u32 = 0;
        unsafe {
            GetTokenInformation(
                token.h_token,
                TokenRestrictedSids,
                std::ptr::null_mut(),
                0,
                &mut needed,
            );
        }
        assert!(
            needed >= std::mem::size_of::<TOKEN_GROUPS>() as u32,
            "TokenRestrictedSids buffer size should be at least TOKEN_GROUPS size, got {needed}"
        );

        let mut buf = vec![0u8; needed as usize];
        let ok = unsafe {
            GetTokenInformation(
                token.h_token,
                TokenRestrictedSids,
                buf.as_mut_ptr() as *mut _,
                needed,
                &mut needed,
            )
        };
        assert!(
            ok != 0,
            "GetTokenInformation(TokenRestrictedSids) must succeed on a restricted token"
        );

        let groups = unsafe { &*(buf.as_ptr() as *const TOKEN_GROUPS) };
        assert_eq!(
            groups.GroupCount, 1,
            "restricted token must carry exactly one restricting SID (the session SID)"
        );
    }
}
```

**What to mirror:**
- `#[cfg(all(test, target_os = "windows"))]` module gate (CLAUDE.md test-environment-isolation: skip on non-Windows).
- Two-call `GetTokenInformation` pattern: first call with null buffer to size, second call with allocated buffer.
- `unsafe { ... }` block + SAFETY comment per CLAUDE.md FFI restriction.
- `.expect("...")` on the constructor (test-only `unwrap_used` is allowed per CLAUDE.md test-mode exception).

**What to change** (per RESEARCH.md:589-612, verbatim sketch):
- Query `TokenIntegrityLevel` (not `TokenRestrictedSids`). Verify `TOKEN_MANDATORY_LABEL` payload's last sub-authority equals `SECURITY_MANDATORY_LOW_RID` (`0x1000`).
- Use `GetSidSubAuthorityCount` + `GetSidSubAuthority` to extract the RID.
- Two additional tests should mirror `restricted_token.rs:209-228`'s drop-lifecycle pattern: `_returns_usable_handle_for_child_spawn` + `_drop_is_null_safe` (already covered by `OwnedHandle` Drop — but explicit regression tests are cheap and lock the contract).

```rust
// Wave 1 new test (sketched from RESEARCH.md:589-612):
#[test]
fn create_low_integrity_primary_token_sets_low_il() {
    let token = create_low_integrity_primary_token()
        .expect("create_low_integrity_primary_token must succeed");
    assert!(!token.0.is_null(), "low-integrity primary token handle is non-null");

    // Query TokenIntegrityLevel — must be Low (0x1000).
    let mut needed: u32 = 0;
    unsafe {
        GetTokenInformation(token.0, TokenIntegrityLevel, std::ptr::null_mut(), 0, &mut needed);
    }
    let mut buf = vec![0u8; needed as usize];
    let ok = unsafe {
        GetTokenInformation(token.0, TokenIntegrityLevel, buf.as_mut_ptr() as *mut _, needed, &mut needed)
    };
    assert!(ok != 0);
    let label = unsafe { &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
    let sub_authority_count = unsafe { *GetSidSubAuthorityCount(label.Label.Sid) };
    let last_sub_authority = unsafe {
        *GetSidSubAuthority(label.Label.Sid, (sub_authority_count - 1) as u32)
    };
    assert_eq!(last_sub_authority, SECURITY_MANDATORY_LOW_RID,
        "duplicated token must be at Low integrity (0x1000)");
}
```

---

### `scripts/test-windows-shell-write-deny.ps1` (Wave 1, live-shell test harness — NEW PATTERN)

**Role:** Manual harness that drives a one-shot script into a sandboxed `nono shell` and asserts NTFS access-denied behavior.
**Data flow:** Build → spawn `nono.exe shell --profile claude-code` with `-Command` injection → capture `$LASTEXITCODE` → exit 0/1/2.

**Analog:** None in codebase. Closest sibling is `scripts/windows-test-harness.ps1`, but that script orchestrates `cargo test` runs — it does NOT drive an interactive `nono shell` session. RESEARCH.md § Acceptance #3 Test Pattern (lines 280-302) drafts the verbatim shape.

**Pattern to ESTABLISH** (RESEARCH.md:284-302, verbatim — this is the genuinely-new pattern Wave 1 introduces):
```powershell
# scripts/test-windows-shell-write-deny.ps1
# Run on Windows test box after fresh `nono.exe` build from Wave 1.
$ErrorActionPreference = 'Continue'
Write-Host "==> Build:"
cargo build -p nono-cli --release --target x86_64-pc-windows-msvc

$nono = ".\target\x86_64-pc-windows-msvc\release\nono.exe"

# Inject a one-shot script into PowerShell that attempts a write outside the grant set.
$test = "Out-File C:\Users\$env:USERNAME\Desktop\nono-acceptance3.txt 'should fail'; if (Test-Path C:\Users\$env:USERNAME\Desktop\nono-acceptance3.txt) { exit 1 } else { exit 42 }"

Write-Host "==> Acceptance #3:"
& $nono shell --profile claude-code --allow-cwd --shell powershell.exe -- -NoLogo -Command $test

if ($LASTEXITCODE -eq 42) { Write-Host "PASS"; exit 0 }
elseif ($LASTEXITCODE -eq 1) { Write-Host "FAIL — write succeeded inside sandbox"; exit 1 }
else { Write-Host "INDETERMINATE — exit $LASTEXITCODE"; exit 2 }
```

**Sibling reference for header/conventions** (`scripts/windows-test-harness.ps1:1-13`):
```powershell
param(
    [ValidateSet("build", "smoke", "integration", "security", "regression", "all")]
    [string]$Suite = "all",
    [string]$LogDir = "ci-logs"
)

$ErrorActionPreference = "Stop"
# Cargo and other native tools write normal progress output to stderr.
# Keep that from being promoted into terminating PowerShell errors while we tee logs.
$PSNativeCommandUseErrorActionPreference = $false

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
```

**What to mirror from sibling:**
- `param(...)` block at top if any params are needed (planner discretion — this script may be parameterless).
- `$ErrorActionPreference = 'Continue'` (NOT `'Stop'` — we WANT non-zero exit codes from the inner shell to bubble up to `$LASTEXITCODE` for evaluation, not terminate the harness).
- `$PSNativeCommandUseErrorActionPreference = $false` to stop cargo/nono progress from being promoted to terminating errors (RESEARCH.md doesn't explicitly require this but it's sibling convention).

**What to add (genuinely new):**
- The one-shot `Out-File ... ; if (Test-Path ...) { exit 1 } else { exit 42 }` injection pattern. This is the load-bearing test logic.
- Distinct exit codes: `42 = PASS`, `1 = FAIL` (write succeeded), `2 = INDETERMINATE` (any other shell exit). The 42 sentinel ensures we don't false-pass on a `Stop`-driven shell exit.
- Read-still-works companion test (RESEARCH.md:312-321):
  ```powershell
  # Inside the same harness OR a sibling acceptance #4 block:
  $claudeJson = "$env:USERPROFILE\.claude\claude.json"
  if (Test-Path $claudeJson) { Get-Content $claudeJson -TotalCount 1 }
  ```

**Caveat (RESEARCH.md Pitfall 4):** `%TEMP%` rendezvous-file accessibility. Wave 1 should include a one-line `tracing::debug!` or visible log line confirming "child connected to pipe" — if absent, the harness exits with a distinct INDETERMINATE message.

---

### `scripts/test-windows-shell-tui.ps1` (Wave 1, manual harness — NEW PATTERN)

**Role:** Launch `claude` inside `nono shell` and verify TUI rendering visually (manual check).
**Data flow:** Spawn → user observes → user types `/quit` then `exit` → user records pass/fail.

**Analog:** None. This is a purely-manual runbook script; the codebase has no precedent for visual-TUI verification harness.

**What to ESTABLISH:**
- Echo a numbered checklist (per RESEARCH.md Open Question 4 baseline at line 749-751):
  1. Launch `nono shell --profile claude-code --allow-cwd`
  2. Run `claude` inside
  3. Observe alternate-screen TUI (logo + chat input box)
  4. Type one message, observe response render
  5. Type `/quit`
  6. Type `exit` from the shell
- Echo PASS/FAIL prompts after each step (since automation can't verify TUI rendering itself).
- Optionally also test `--shell C:\Windows\System32\cmd.exe` per RESEARCH.md Open Question 3 line 745-746.

**Note for planner:** This script may be reduced to a `runbook.md` — the only "automation" is sequencing the steps. Planner discretion per CONTEXT.md D-510 (`<discretion>` block).

---

### `.planning/PROJECT.md` SHELL-01 row (Wave 1 first task — bookkeeping correction; Wave 1 last task — outcome flip)

**Role:** Validated-requirement table row.
**Data flow:** None (text replacement).

**Analog:** Same file lines 60-100, the surrounding row pattern.

**Pattern to mirror** (`.planning/PROJECT.md:71`, the row to be updated):
```markdown
- ✔ **SHELL-01** — `nono shell` interactive ConPTY on Windows 10 17763+ — v2.0 Phase 08
```

**Surrounding-row examples** (lines 69-78) showing the established shape:
```markdown
- ✔ **WRAP-01** — `nono wrap` on Windows (Direct strategy + Job Object + WFP + canonical help text) — v2.0 Phases 07, 14-02
- ✔ **SESS-01/02/03** — `nono logs`, `nono inspect`, `nono prune` on Windows session records — v2.0 Phase 07 (SESS-03 live UAT waived as v2.0-known-issue)
- ✔ **SHELL-01** — `nono shell` interactive ConPTY on Windows 10 17763+ — v2.0 Phase 08
- ✔ **PORT-01** — port-level WFP allowlists (`--allow-port`, bind/connect) — v2.0 Phase 09
...
- ✔ **DETACHED-FIX-01** — detached-supervisor + ConPTY + restricted-token architecture fix (direction-b: gated PTY-disable + null-token + AppID WFP on the Windows detached path)... v2.1 Phase 15
```

**What to mirror:**
- Bullet shape: `- <STATUS> **REQ-ID** — short description — vX.Y Phase NN`.
- Status markers visible in the file: `✔` (validated), `⚠` (rework — used elsewhere in PROJECT.md), `✘` (deferred — used in roadmap).
- Long description carries the technical evidence (e.g., DETACHED-FIX-01's parenthetical waiver clause is the closest precedent for Wave 1's outcome row when SHIP-success path is taken).

**Wave 1 first task — flip to needs-rework:**
```markdown
- ⚠ **SHELL-01** — `nono shell` interactive ConPTY on Windows 10 17763+ — v2.0 Phase 08 claim invalidated by 2026-05-07 debug session `nono-shell-status-dll-init-failed` (WRITE_RESTRICTED + ConPTY = 0xC0000142); needs-rework pending Phase 30 outcome
```

**Wave 1 last task — flip to validated v2.X Phase 30 (success path):**
```markdown
- ✔ **SHELL-01** — `nono shell` interactive ConPTY on Windows 10 17763+ via Low-IL primary token (Phase 30 D-01); per-session WFP SID waived (AppID fallback, parallel to Phase 15 detached path); mandatory-label NO_WRITE_UP enforces write-deny outside grant set — v2.X Phase 30
```

**Wave 2 last task — flip to deferred (failure path):**
```markdown
- ✘ **SHELL-01** — `nono shell` on Windows is structurally incompatible with simultaneous WRITE_RESTRICTED + ConPTY at user-mode (Phase 30 evidence); deferred to v3.0 kernel mini-filter driver work
```

---

### `.planning/STATE.md` key-decisions block (Wave 1 last task — bookkeeping)

**Role:** Session continuity and milestone snapshot.
**Data flow:** None (text replacement and append).

**Analog:** Same file. The `### Key Decisions (vX.Y)` blocks at lines 61, 77, 91, 95.

**Pattern to mirror** (the v2.2 entry at line 91-93 is the closest, dense-narrative shape):
```markdown
### Key Decisions (v2.2)

- **Phase 23 Plan 23-01 (REQ-AUD-05) Windows AIPC ledger emission:** Wires `Option<&Arc<Mutex<AuditRecorder>>>` end-to-end through `supervised_runtime.rs:235` (Mutex::new → Arc::new(Mutex::new(...))) → `exec_strategy.rs:486` → ... [4-paragraph dense narrative with file:line citations, structural grep invariants, deferred items, commits]
```

**What to mirror:**
- Heading: `### Key Decisions (vX.Y)` — Wave 1 picks v2.3 OR v2.4 per CONTEXT.md `<phase_placement>` line 6 (user decides at `/gsd-phase add 30`).
- Dense single-bullet entry per phase (NOT split into sub-bullets within a phase).
- File:line citations for every claim.
- Structural grep invariants where useful (e.g., `grep -c "create_low_integrity_primary_token" crates/nono-cli/src/`).
- Commit hashes at the end (`Commits: aaaa, bbbb, cccc.`).
- Phase progress fragment (`Phase 30 progress N/M plans`).

**What to add (genuinely new content for Phase 30):**
- D-01..D-10 reference per CONTEXT.md.
- Parallel to Phase 15 waiver (cite `windows-supervised-exec-cascade.md` resolution doc).
- Outcome (success or deferred-to-v3.0).

**Stopped At line:** Update from current `stopped_at: Phase 27.2 context gathered` to `stopped_at: Phase 30 complete` (success path) or `stopped_at: Phase 30 documented failure-mode (deferred to v3.0)` (failure path). The `last_updated` ISO timestamp at line 7 must also be refreshed.

---

### `docs/cli/development/windows-poc-handoff.mdx` security-envelope paragraph (Wave 1 last task — docs)

**Role:** Operator-facing security-envelope explanation.
**Data flow:** None (text insertion).

**Analog primary:** Phase 15 detached-path waiver in `windows-supervised-exec-cascade.md:241-243`:
```markdown
- **Low-Integrity isolation**: waived. Null token inherits caller IL. Job Object + filesystem sandbox (CapabilitySet) remain primary isolation.
- **Per-session SID WFP**: waived. Detached children share one AppID WFP filter. Still kernel-enforced; requires `nono-wfp-service` running for network enforcement.
- Non-detached `nono run` and `nono shell` retain the full WRITE_RESTRICTED + session-SID + ConPTY configuration — unchanged.
```

**Analog secondary (in-doc location):** Same file `docs/cli/development/windows-poc-handoff.mdx:10-17`, the existing `<Note>` block, for tone and Markdown shape:
```markdown
<Note>
**Two facts that affect the POC happy path on Windows:**

1. **Profile-backed runs work**, and both `nono shell` and `nono wrap` are supported on Windows 10 build 17763+ via ConPTY. The 0.37.x binary's `setup --check-only` confirms this. Some legacy docs imply otherwise — those docs are stale on the profile/shell/wrap question.
2. **`nono run -- <TUI>` cannot host an interactive TUI agent on Windows.** ...

For interactive Claude sessions on Windows, use `nono shell --profile claude-code` and start `claude` from inside the sandboxed shell. That's the path this cookbook recommends throughout.
</Note>
```

**Tertiary (in-doc keep-alive):** `docs/cli/development/windows-poc-handoff.mdx:233-239` "Known limitation: `nono run` cannot host TUI agents" section — RESEARCH.md § Cookbook Rollback Path notes this section is **factually correct content** that should be PRESERVED on both Wave 1 success and Wave 2 failure paths.

**Wave 1 success-path text** (RESEARCH.md:342-353, verbatim starting point — planner has full discretion to refine):
```markdown
**Security envelope under `nono shell` on Windows (Phase 30):**
The sandboxed shell child runs under a Low Integrity primary token. Filesystem
write enforcement comes from per-path mandatory integrity labels (NO_WRITE_UP
mask) — kernel-level access checks deny writes to paths outside the grant set
before DACL evaluation. Read access to granted paths uses the same mandatory-
label mechanism (NO_READ_UP for Write-only grants; pass-through for ReadWrite
grants). Per-session WFP differentiation via the synthetic restricting SID is
NOT used on this path; outbound network filtering falls back to AppID-based
filtering (same waiver Phase 15 documented for the `nono run --detached` path).
The Claude Code PreToolUse hook is defense-in-depth on top of the OS-level
write-deny.
```

**What to mirror:**
- Phase 15's two-bullet waiver structure (waived-property + replacement-mechanism).
- Honest disclosure of what's enforced at OS level vs what relies on the hook (CONTEXT.md D-06 line 55: hook is defense-in-depth, NOT primary boundary).
- Citation of Phase 30 D-01 and parallel to Phase 15 detached-path precedent.

**What to add specifically for Wave 1:**
- The Pitfall 3 honesty caveat (RESEARCH.md:647-654): mandatory-label NO_WRITE_UP enforces ONLY OUTSIDE the grant set (subject IL == object IL inside grants → MIC pre-check passes, write goes through; writes inside grants are bounded by `CapabilitySet` contract, not by MIC). The cookbook text MUST distinguish.

**Insertion location:** Between Step 4 and Step 5, OR appended to the top-of-doc `<Note>` block. Planner discretion per RESEARCH.md:340.

**Wave 2 failure-path (cookbook revert):** RESEARCH.md:357-364 prescribes Option Rev-B (text replacement, NOT `git revert 0c69bd4b`) — strip the `<Note>` recommendation, Step 4 instruction, Step 5 interactive-verification block, and Step 6 row. Add a new section: `nono shell on Windows is deferred to v3.0`. KEEP the lines 233-239 "Known limitation" section.

---

### `.planning/debug/nono-shell-status-dll-init-failed.md` status flip (Wave 1 — frontmatter edit + Wave 1 close — move to `resolved/`)

**Role:** Debug-session lifecycle metadata.
**Data flow:** None (frontmatter YAML edit).

**Analog primary:** `.planning/debug/resolved/windows-supervised-exec-cascade.md:1-14` (Phase 15's resolved session):
```yaml
---
slug: windows-supervised-exec-cascade
status: resolved
trigger: Windows supervised execution cascade — after fixing token UAF in spawn_windows_child (eb4730c / quick 260417-wla), two more blockers block every `nono run` on Windows
created: 2026-04-17
updated: 2026-04-18
branch: windows-squash
head: 2c414d8
milestone: v2.0
milestone_blocker: false
resolved_by: phase-15-plan-02
related_phase: 15-detached-console-conpty-investigation
related_quick: 260417-wla
---
```

**Analog secondary:** `.planning/debug/resolved/supervisor-pipe-access-denied.md:1-11` (Phase 21 resolution):
```yaml
---
slug: supervisor-pipe-access-denied
status: resolved
trigger: Phase 21 Plan 21-05 Task 2 HUMAN-UAT re-run
created: "2026-04-20T22:04:29Z"
updated: "2026-04-21T12:00:00Z"
branch: windows-squash
head_commit: e4c1bfa
related_phase: 21-windows-single-file-grants
related_uat: .planning/phases/18-extended-ipc/18-HUMAN-UAT.md (G-01)
---
```

**Current state of the file** (`.planning/debug/nono-shell-status-dll-init-failed.md:1-12`, already partially flipped):
```yaml
---
slug: nono-shell-status-dll-init-failed
status: architecture-decided-pending-implementation
resolution_doc: .planning/phases/30-windows-nono-shell-architecture/30-CONTEXT.md
checkpoint_outcome: |
  H1 refuted (cmd.exe also fails); H7 narrowed to "PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
  + WRITE_RESTRICTED + session-SID = 0xC0000142". ...
trigger: "nono shell --profile claude-code --allow-cwd silently exits..."
created: 2026-05-07T19:30:00Z
updated: 2026-05-07T19:55:00Z
...
```

**What to mirror (Wave 1 close — file move + frontmatter flip):**
- File MOVE: `.planning/debug/nono-shell-status-dll-init-failed.md` → `.planning/debug/resolved/nono-shell-status-dll-init-failed.md`.
- Set `status: resolved`.
- Add `resolved_by: phase-30-plan-NN` field (planner determines plan number).
- Update `updated:` to the resolution timestamp.
- Add `related_phase: 30-windows-nono-shell-architecture`.
- Drop `checkpoint_outcome` (no longer needed once resolved) OR retain as historical note. Phase 15's resolved session does NOT carry it.

**What to change between intermediate and final states:**
- Wave 1 first task: status `paused-pending-architecture-review` → `architecture-decided-pending-implementation` (already done — see line 3 of current file). Resolution doc field already points at CONTEXT.md.
- Wave 1 close: status `architecture-decided-pending-implementation` → `resolved`. File moves to `resolved/`. The Wave 1 outcome (success path: cascade arm shipped; failure path: deferred-to-v3.0) goes into a final `## Resolution` section at the bottom of the file.

---

### `.planning/phases/30-windows-nono-shell-architecture/30-FIELD-SMOKE.md` (Wave 1, optional runbook — planner discretion)

**Role:** Field-test checklist for Acceptance #1, #2 (and #3 if not folded into the harness script).
**Data flow:** None (markdown checklist).

**Analog:** Phase 15's smoke-gate evidence table at `.planning/debug/resolved/windows-supervised-exec-cascade.md:115-130` (the test matrix with rows like `| Token | PTY | Exit |`).

**Smoke-gate-table pattern to mirror:**
```markdown
| Token | PTY | Detached | Outcome (exit code / behavior) |
|---|---|---|---|
| WRITE_RESTRICTED + session-SID | Some (ConPTY) | Yes | 0xC0000142 (STATUS_DLL_INIT_FAILED) |
| Low-IL primary | Some (ConPTY) | No | (Wave 1 fills in) |
| ...
```

**Not load-bearing — planner may opt to fold the field-smoke list into the commit body of the cascade-arm change.** RESEARCH.md:510 (Wave 0 Gaps) marks this as "planner discretion."

---

### `crates/nono-cli/src/supervised_runtime.rs` (Wave 2, conditional — production code, hypothetical fix point)

**Role:** Per-session named-object DACL adjustment OR alternative gate fix surfaced by Wave 2 ProcMon.
**Data flow:** TBD by Wave 2 evidence.

**Analog:** Same file `supervised_runtime.rs:95-111` (`should_allocate_pty()` Windows arm — Phase 15's gate). Hypothetical Wave 2 fix would extend this arm with another gate condition, OR add a new function alongside it.

**Pattern to ESTABLISH if Wave 2 surfaces a sixth option:** the shape depends on the surfaced mechanism:
- "Add DACL ACE to per-session `\BaseNamedObjects\` subdir" → setup-time helper in `crates/nono-cli/src/setup.rs` style (analog there).
- "Sequencing fix: create pseudoconsole BEFORE dropping integrity" → reordering in `pty_proxy::open_pty()` callers (analog: `exec_strategy_windows/launch.rs:1178-1276` PTY branch).
- "Broker-process pattern" → new module entirely; no analog.

**RESEARCH.md § ProcMon Trace Plan (lines 209-263) is the only reference; cannot pre-bind to a code analog.**

---

## Shared Patterns

### OwnedHandle RAII discipline (production code)

**Source:** `crates/nono-cli/src/exec_strategy_windows/launch.rs:1131-1162`, plus the comment block at `launch.rs:1126-1130`.

**Apply to:** ANY production code path that obtains a Windows HANDLE from a fallible constructor and passes the raw HANDLE to `CreateProcess*W`.

**Concrete excerpt** (already cited in arm #6 section above; reproduced for shared-pattern reference):
```rust
let _restricted_holder: Option<restricted_token::RestrictedToken>;
let _low_integrity_holder: Option<OwnedHandle>;
// ...
} else if pty.is_some() {
    let holder = create_low_integrity_primary_token()?;
    let raw = holder.0;
    _low_integrity_holder = Some(holder);
    _restricted_holder = None;
    raw
}
// NOTE: do NOT re-wrap h_token in a fresh OwnedHandle — the holder above
// already owns the close. A second wrapper would double-close on Drop.
```

**Rule:**
- Bind every fallible HANDLE constructor result to a NAMED local (not a temporary).
- Read the raw HANDLE into a separate `let raw = ...;` BEFORE moving the holder into its `Option`.
- Set the OTHER holders (in cascade contexts) to `None` explicitly.
- Never re-wrap a HANDLE owned by a holder; CloseHandle would run twice on Drop.

**Source of rule:** Quick task `260417-wla` (commit `eb4730c`) — see `.planning/debug/resolved/windows-supervised-exec-cascade.md` § "Bug #1: Token handle use-after-close" at line 73.

---

### Test env-var save/restore (test code)

**Source:** `crates/nono-cli/src/test_env::{lock_env, EnvVarGuard}` (per `launch.rs:1411`).

**Apply to:** ANY test that touches `HOME`, `TMPDIR`, `XDG_CONFIG_HOME`, `NONO_DETACHED_LAUNCH`, or any env var. CLAUDE.md `## Coding Standards` mandates this — bare `std::env::set_var` causes flaky failures because Rust runs unit tests in parallel within the same process.

**Concrete excerpt** (`launch.rs:1413-1419`):
```rust
#[test]
fn returns_false_when_env_unset() {
    let _lock = lock_env();
    let g = EnvVarGuard::set_all(&[("NONO_DETACHED_LAUNCH", "1")]);
    g.remove("NONO_DETACHED_LAUNCH");
    assert!(!is_windows_detached_launch());
}
```

**Rule:**
- Acquire `let _lock = lock_env();` at the top of any env-var-touching test.
- Use `EnvVarGuard::set_all(&[(...)])` to set values; `g.remove(...)` to clear them within the same scope.
- Both `_lock` and `_g` (or `g`) must live until end of test — bind to named locals.

---

### Error handling: `NonoError::SandboxInit` for token construction (production code)

**Source:** `launch.rs:1036-1040` (`create_low_integrity_primary_token` already follows this).

**Apply to:** Any new FFI failure path in the cascade.

**Concrete excerpt:**
```rust
if opened == 0 {
    return Err(NonoError::SandboxInit(format!(
        "Failed to open Windows process token for low-integrity launch (GetLastError={})",
        unsafe { GetLastError() }
    )));
}
```

**Rule:**
- Every Win32 API failure returns `NonoError::SandboxInit(format!(...))` with `GetLastError()` interpolated.
- Use `?` propagation upward.
- Never `unwrap()` / `expect()` outside test code (CLAUDE.md `## Coding Standards`).

---

### `#[cfg(all(test, target_os = "windows"))]` gating (test code)

**Source:** `crates/nono-cli/src/exec_strategy_windows/restricted_token.rs:123` and `launch.rs:1439`.

**Apply to:** Any test that exercises Windows-only FFI (`GetTokenInformation`, `CreateRestrictedToken`, `SetTokenInformation`, etc.).

**Rule:** Module attribute `#[cfg(all(test, target_os = "windows"))] mod tests { ... }` — keeps non-Windows builds clean and avoids "unused-import" warnings on cross-platform builds.

---

### Debug-session resolution metadata (bookkeeping)

**Source:** `.planning/debug/resolved/windows-supervised-exec-cascade.md:1-14` and `supervisor-pipe-access-denied.md:1-11`.

**Apply to:** `.planning/debug/nono-shell-status-dll-init-failed.md` final flip + move to `resolved/`.

**Rule (frontmatter shape):**
```yaml
---
slug: <unchanged>
status: resolved
trigger: <unchanged>
created: <unchanged>
updated: <ISO timestamp of resolution>
branch: <branch of resolving commit, e.g. windows-squash>
head_commit: <commit hash of resolving merge>
milestone: <milestone in which resolved>
resolved_by: phase-30-plan-NN  (planner fills NN)
related_phase: 30-windows-nono-shell-architecture
---
```

Plus a `## Resolution` section at the bottom of the file summarizing outcome.

---

## Files Without Analogs

These two scripts establish genuinely-new patterns Wave 1 introduces. The codebase has no precedent for either; the closest sibling (`scripts/windows-test-harness.ps1`) is a cargo-test orchestrator, not a live-shell driver:

| File | Role | Why no analog |
|------|------|---------------|
| `scripts/test-windows-shell-write-deny.ps1` | live-shell test harness | No existing script drives an interactive `nono shell` session with stdin scripting. RESEARCH.md § Acceptance #3 Test Pattern (lines 280-302) is the ONLY blueprint. Cargo integration tests exist for `nono.exe run -- ...` (one-shot) but cannot drive `nono shell` cleanly because `nono shell` is interactive-by-design and Cargo can't supply ConPTY input deterministically. |
| `scripts/test-windows-shell-tui.ps1` | manual TUI verification runbook | No precedent in the codebase for visual-rendering verification. The script is essentially a sequenced runbook with PASS/FAIL prompts; planner may collapse it into a `runbook.md` instead. RESEARCH.md Open Question 4 (lines 749-751) drafts the user-interaction baseline. |

The Wave 2 ProcMon analysis files (if Wave 2 fires) are also without analog — RESEARCH.md § ProcMon Trace Plan is the sole reference.

---

## Metadata

**Analog search scope:** `crates/nono-cli/src/exec_strategy_windows/`, `crates/nono-cli/tests/`, `crates/nono/src/sandbox/windows.rs`, `crates/nono/src/supervisor/socket_windows.rs`, `scripts/`, `docs/cli/development/`, `.planning/debug/`, `.planning/`, `.planning/phases/`.
**Files scanned:** ~22 (4 production-code files for token cascade + RAII; 2 test fixtures for unit-test patterns; 2 PowerShell scripts; 4 docs files; 4 debug-session frontmatters; 4 phase 30 planning artifacts; 2 PROJECT.md / STATE.md bookkeeping files).
**Pattern extraction date:** 2026-05-07
**Confidence:** HIGH for Wave 1 (every modified file has at least one in-tree analog or a verbatim RESEARCH.md sketch). LOW for Wave 2 (exploratory; no analog by definition).
