---
quick_id: 260508-m99
slug: broker-process-poc-minimal-rust-binary-t
description: "broker-process PoC — validates RESEARCH.md assumption A1 (Low-IL child skips CSRSS ALPC attach when inheriting console)"
date: 2026-05-08
type: research-code
mode: quick
---

# Quick Task: Broker-process PoC

## Objective

Build a standalone Rust binary that reproduces the broker-process pattern's core mechanism: a Medium-IL parent allocates a console, duplicates and downgrades its own token to Low IL, then spawns `powershell.exe` with no new-console flag so the child inherits the already-attached console.

The user runs the binary on a Windows test box and reports the exit code. That outcome determines whether to commit to Phase 31 (~7 more days) or pursue an alternative path.

**Assumption being validated:** RESEARCH.md §Assumptions Log A1 — `KernelBase!ConClntInitialize` skips the CSRSS ALPC port connection when a child process inherits the parent's console rather than allocating one fresh.

**Decision path:**
- PASS (exit 0) → commit to Phase 31 broker-process implementation
- FAIL-A (exit 0xC0000142) → broker pattern not viable; escalate to discuss-phase for AppContainer vs deferral
- FAIL-B (other code) → new failure mode; capture ProcMon trace and analyze

---

## Tasks

### Task 1: Scaffold standalone PoC crate

**Files:**
```
.planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/poc-broker/Cargo.toml
.planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/poc-broker/src/main.rs
```

**Action:**

Create a standalone Cargo crate that is NOT a member of the nono workspace.

`Cargo.toml` must contain:
- `[workspace]` section (empty — this is the "I am my own workspace" marker that prevents Cargo from crawling up to find the parent workspace)
- `name = "poc-broker"`, `version = "0.1.0"`, `edition = "2021"`
- `[target.'cfg(windows)'.dependencies]` section with `windows-sys = { version = "0.59", features = ["Win32_Foundation", "Win32_Security", "Win32_System_Threading", "Win32_System_Console"] }` — matches the workspace pin and includes exactly the feature flags needed
- `[[bin]]` entry: `name = "poc-broker"`, `path = "src/main.rs"`

`src/main.rs` skeleton (verifies build toolchain works before Win32 wiring):

```rust
fn main() {
    println!("[POC] starting — skeleton build OK");
}
```

**Acceptance:**
- `Cargo.toml` exists with `[workspace]` section and `windows-sys = "0.59"` dependency under `[target.'cfg(windows)'.dependencies]`
- `cargo build --release` from inside `poc-broker/` exits 0 on Windows
- `cargo build` from the nono workspace root does NOT pick up `poc-broker` (workspace root `Cargo.toml` `[workspace.members]` is unchanged — confirm by running `cargo metadata --no-deps --manifest-path Cargo.toml` from repo root and grepping for `poc-broker`; it must not appear)
- `target/release/poc-broker.exe` runs and prints `[POC] starting`

---

### Task 2: Implement Win32 broker mechanism

**Files:**
```
.planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/poc-broker/src/main.rs
```

**Action:**

Replace the skeleton `main.rs` with the full implementation. Target is ~100-150 lines including comments and error handling. This is research code: `.expect()` with descriptive messages is acceptable — panic on unexpected Win32 failure is the correct behavior for a PoC whose sole purpose is pass/fail detection.

**Required imports** (derive from `launch.rs` reference patterns in `exec_strategy_windows/mod.rs:70-75` and `launch.rs:1-12`):

```rust
#[cfg(windows)]
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, BOOL};
#[cfg(windows)]
use windows_sys::Win32::Security::{
    CreateWellKnownSid, DuplicateTokenEx, OpenProcessToken, SecurityAnonymous,
    SetTokenInformation, TokenIntegrityLevel, TokenPrimary, WinLowLabelSid,
    SECURITY_IMPERSONATION_LEVEL, SECURITY_MAX_SID_SIZE,
    TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL,
    TOKEN_QUERY, SE_GROUP_INTEGRITY,
};
#[cfg(windows)]
use windows_sys::Win32::System::Console::AllocConsole;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, WaitForSingleObject,
    PROCESS_INFORMATION, STARTUPINFOW, INFINITE,
};
```

**Implementation sequence** (mirror `create_low_integrity_primary_token` from `launch.rs:1075-1167` for token steps):

1. `AllocConsole()` — idempotent if parent already has a console; returns BOOL, non-zero = success or already-attached. Check but do not fatal on failure (parent's inherited console is equally valid).

2. `OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT, &mut h_token)` — fatal on failure.

3. `DuplicateTokenEx(h_token, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, null, SecurityAnonymous, TokenPrimary, &mut h_new_token)` — fatal on failure. CR-01 hygiene: `SecurityAnonymous` is the correct impersonation level for a primary token (per RESEARCH.md §1a and `launch.rs:1103-1108`).

4. `CreateWellKnownSid(WinLowLabelSid, null, sid_buf.as_mut_ptr(), &mut sid_size)` — fatal on failure.

5. Construct `TOKEN_MANDATORY_LABEL` struct inline (mirror `launch.rs:1138-1149`):
   - `label_size = size_of::<TOKEN_MANDATORY_LABEL>() + sid_size`
   - Allocate `label_buffer: Vec<u8>` of that size
   - Write SID after the struct header
   - Set `Label.Sid` to point into buffer, `Label.Attributes = SE_GROUP_INTEGRITY as u32`

6. `SetTokenInformation(h_new_token, TokenIntegrityLevel, label_ptr, label_size)` — fatal on failure.

7. Construct a zeroed `STARTUPINFOW` with `cb = size_of::<STARTUPINFOW>() as u32`. Leave all other fields zero — no console flags, no pseudo-console attribute. This is the critical flag combination being tested: the child inherits the parent's console via handle inheritance, NOT via a new console allocation.

8. `CreateProcessAsUserW(h_new_token, null, cmd_line.as_mut_ptr(), null, null, 0 /* bInheritHandles=FALSE — no specific handle list */, 0 /* no CREATE_NEW_CONSOLE, no DETACHED_PROCESS */, null, null, &si, &mut pi)` where `cmd_line` is `"powershell.exe -NoLogo"` encoded as null-terminated UTF-16 (`OsStr::new("powershell.exe -NoLogo").encode_wide().chain(Some(0)).collect::<Vec<u16>>()`). Fatal on failure with `GetLastError()` in message.

9. Print immediately after spawn:
   ```
   [POC] Mechanism: AllocConsole + DuplicateTokenEx(SecurityAnonymous, TokenPrimary) + SetTokenInformation(Low) + CreateProcessAsUserW(no console flags)
   [POC] Child PID: {pi.dwProcessId}
   [POC] Waiting for child...
   ```

10. `WaitForSingleObject(pi.hProcess, INFINITE)` — fatal on failure.

11. `GetExitCodeProcess(pi.hProcess, &mut exit_code)` — fatal on failure.

12. Print results and interpretation:
    ```
    [POC] Child exit code: {exit_code:#010x} ({exit_code})
    ```
    Then match on exit_code:
    - `0` → `[POC] PASS — broker pattern viable; child survived KernelBase DllMain at Low-IL`
    - `0xC0000142` (which is `u32` wrapping of `-1073741502i32` = `3221225794u32`) → `[POC] FAIL variant A — CSRSS still denies Low-IL child even with inherited console; broker pattern NOT viable without further mechanism`
    - anything else → `[POC] FAIL variant B — unexpected exit code; capture ProcMon trace and analyze`

13. Cleanup: `CloseHandle(pi.hThread)`, `CloseHandle(pi.hProcess)`, `CloseHandle(h_new_token)`, `CloseHandle(h_token)`.

**All `unsafe` blocks must have `// SAFETY:` comments** explaining why each Win32 FFI call is safe at that call site. Mirror the style from `launch.rs:1077-1089`. Minimum one `// SAFETY:` per `unsafe { }` block.

**Error handling pattern** for each Win32 call:
```rust
if result == 0 {
    eprintln!("[POC] FATAL: SomeFn failed (GetLastError={})", unsafe { GetLastError() });
    std::process::exit(1);
}
```

**Note:** `0xC0000142u32` — verify the exact `u32` bit pattern in a comment in the match arm:
```rust
// STATUS_DLL_INIT_FAILED = 0xC0000142 = 3221225794u32
// This is the exit code when KernelBase DllMain fails CSRSS ALPC attach.
```

**Acceptance:**
- `cargo build --release` from `poc-broker/` succeeds on Windows (exit 0)
- Source is < 200 lines including comments
- All `unsafe` blocks have `// SAFETY:` comments
- Match arm for `0xC0000142` is present with the decimal value in a comment
- No `.unwrap()` without a descriptive `.expect("message")` — every panic site has a diagnostic string
- `cargo clippy` from `poc-broker/` produces no errors (warnings about unused cfg attributes on non-Windows are acceptable)

---

### Task 3: User-runnable smoke instructions

**Files:**
```
.planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/README.md
```

**Action:**

Write a README that the user can follow to build, run, and interpret the PoC. No prior context assumed — treat it as a standalone document.

Required sections:

**Build**
```
cd .planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/poc-broker
cargo build --release --target x86_64-pc-windows-msvc
```
Note: must be run from a Windows shell (PowerShell or cmd) with the MSVC toolchain installed. The crate has Windows-only dependencies — `cargo build` on Linux/macOS will succeed for the skeleton but `--target x86_64-pc-windows-msvc` is the intended build target.

**Run**
```
.\target\release\poc-broker.exe
```
Run from a PowerShell or cmd window opened at Medium IL (normal user session — do NOT run as Administrator). Expected: a new PowerShell prompt opens in the SAME console window. Type `exit` and press Enter. PoC prints the exit code and interpretation.

**Verify IL** (inside the spawned PowerShell child)
```powershell
whoami /groups | Select-String "Mandatory Label"
```
Expected output on PASS: `Mandatory Label\Low Mandatory Level`. If it shows `Medium Mandatory Level`, the token IL was not applied correctly — report as a separate failure mode.

**Expected outputs table:**

| Scenario | Exit code | PoC output line |
|----------|-----------|-----------------|
| PASS | `0x00000000` | `[POC] PASS — broker pattern viable; child survived KernelBase DllMain at Low-IL` |
| FAIL-A | `0xC0000142` | `[POC] FAIL variant A — CSRSS still denies Low-IL child...` |
| FAIL-B | any other | `[POC] FAIL variant B — unexpected exit code; capture ProcMon trace and analyze` |

**On failure, capture:**
1. Full PoC stdout/stderr: `.\poc-broker.exe > poc-out.txt 2>&1`
2. ProcMon trace: filter on `Process Name` = `powershell.exe`, capture from launch to exit. Export as CSV. Look for `NtAlpcConnectPort` with `ACCESS DENIED` result in the child's first second of lifetime.
3. Report: the exact `[POC] Child exit code:` line from stdout.

**Cross-references:**
- RESEARCH.md §6 (PoC scope and expected outcomes): `.planning/quick/260508-lqh-scope-phase-31-broker-process-implementa/RESEARCH.md`
- RESEARCH.md §Assumptions Log A1 (the assumption this PoC validates): same file, section "Assumptions Log", row A1
- RESEARCH.md §1b (mechanism viability analysis for console inherit path)
- Phase 30 field evidence: `.planning/phases/30-windows-nono-shell-architecture/30-WAVE-2-PROCMON.md`

**Acceptance:**
- README.md exists with all four sections: Build, Run, Verify IL, Expected outputs table
- Cross-references to RESEARCH.md §6 and §Assumptions Log A1 are present (with file paths, not URLs)
- Failure-mode table covers all three outcomes (PASS, FAIL-A, FAIL-B)
- ProcMon capture instructions are present for the failure case

---

## Output

After all three tasks complete, create `.planning/quick/260508-m99-broker-process-poc-minimal-rust-binary-t/SUMMARY.md` with:
- What was built (crate path, binary name, line count)
- Build status (confirmed on Windows or pending field test)
- Next step: user runs `poc-broker.exe` on Windows test box and reports exit code
- Link back to RESEARCH.md §8 decision matrix for the decision path once field result is known

Update `.planning/STATE.md` Quick Tasks Completed table to record `260508-m99` as done.

Note: the smoke test itself (running `poc-broker.exe` on Windows and observing the exit code) is a USER action that happens AFTER this task ships. The executor's job ends at: all files committed, README in place, binary buildable.

---

## Acceptance Criteria

- [ ] `poc-broker/Cargo.toml` exists with `[workspace]` empty section and `windows-sys = "0.59"` under `[target.'cfg(windows)'.dependencies]`
- [ ] `poc-broker/src/main.rs` exists, < 200 lines, all `unsafe` blocks have `// SAFETY:` comments
- [ ] `cargo build --release` from `poc-broker/` produces `poc-broker.exe` (Windows)
- [ ] `cargo build` from nono workspace root exits 0 and does NOT include `poc-broker` in workspace members (no contamination)
- [ ] `0xC0000142` match arm is present with `STATUS_DLL_INIT_FAILED` comment and decimal equivalent
- [ ] `AllocConsole` + `DuplicateTokenEx(SecurityAnonymous, TokenPrimary)` + `SetTokenInformation(Low)` + `CreateProcessAsUserW` sequence is complete
- [ ] `README.md` documents build, run, verify-IL, and failure-mode table with RESEARCH.md cross-references
- [ ] Task dir committed atomically with message: `poc(260508-m99): broker-process PoC — validates RESEARCH.md A1 console-inherit mechanism`
- [ ] `STATE.md` Quick Tasks Completed table updated
