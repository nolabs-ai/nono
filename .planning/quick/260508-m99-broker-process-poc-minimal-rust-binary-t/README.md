# Broker-Process PoC — Console Inheritance at Low IL

**Purpose:** Validate RESEARCH.md Assumption A1: `KernelBase!ConClntInitialize` skips the
CSRSS ALPC port connection when a child process inherits the parent's already-attached console
rather than allocating one fresh. This is the core mechanism assumption for Phase 31.

**Decision path once you have a result:**
- PASS (exit 0) → commit to Phase 31 broker-process implementation (~7 more days)
- FAIL-A (`0xC0000142`) → broker pattern not viable; escalate discuss-phase for AppContainer vs deferral
- FAIL-B (any other code) → new failure mode; capture ProcMon trace and report

---

## Build

Must be run from a Windows shell (PowerShell or cmd) with the MSVC toolchain installed.
The crate has Windows-only dependencies — `windows-sys 0.59` is only linked on Windows targets.

```powershell
cd .planning\quick\260508-m99-broker-process-poc-minimal-rust-binary-t\poc-broker
cargo build --release --target x86_64-pc-windows-msvc
```

The `[workspace]` marker in `Cargo.toml` prevents Cargo from crawling up to the nono parent
workspace. Build must be run from inside the `poc-broker\` directory, not from the repo root.

---

## Run

Open a PowerShell or cmd window as a **normal user** (Medium Integrity Level).
Do NOT run as Administrator — the test is specifically about the Medium→Low spawn path.

```powershell
.\target\release\poc-broker.exe
```

**What happens:** The broker attaches to the console at Medium IL, duplicates its own token,
lowers the token to Low IL, then spawns `powershell.exe -NoLogo` with `dwCreationFlags=0`
(no `CREATE_NEW_CONSOLE`, no `DETACHED_PROCESS`). The child inherits the broker's console.
The broker waits for the child to exit, then prints the exit code and interpretation.

If `PASS`: a new PowerShell prompt opens in the SAME console window. Type `exit` and press Enter.

---

## Verify IL

Inside the spawned PowerShell child, before typing `exit`, run:

```powershell
whoami /groups | Select-String "Mandatory Label"
```

**Expected on PASS:** `Mandatory Label\Low Mandatory Level`

If it shows `Medium Mandatory Level`, the `SetTokenInformation(TokenIntegrityLevel)` call
did not take effect — report as a separate failure mode distinct from PASS/FAIL-A/FAIL-B.

---

## Expected Outputs

| Scenario | Exit code | PoC output line |
|----------|-----------|-----------------|
| PASS | `0x00000000` (0) | `[POC] PASS — broker pattern viable; child survived KernelBase DllMain at Low-IL` |
| FAIL-A | `0xC0000142` (3221225794) | `[POC] FAIL variant A — CSRSS still denies Low-IL child even with inherited console; broker pattern NOT viable without further mechanism` |
| FAIL-B | any other | `[POC] FAIL variant B — unexpected exit code {code}; capture ProcMon trace and analyze` |

`0xC0000142` is `STATUS_DLL_INIT_FAILED` — the NTSTATUS code set when `KernelBase!DllMain`
returns `FALSE` because `ConClntInitialize` could not complete the CSRSS ALPC attach at Low IL.

---

## On Failure — Capture Instructions

1. **Full stdout/stderr:**
   ```powershell
   .\poc-broker.exe > poc-out.txt 2>&1
   Get-Content poc-out.txt
   ```

2. **ProcMon trace:**
   - Open Process Monitor (Sysinternals)
   - Filter: `Process Name` is `powershell.exe`
   - Start capture, then run `.\poc-broker.exe`
   - Stop capture when PoC exits
   - Look for `NtAlpcConnectPort` with `ACCESS DENIED` result in the first second of PowerShell's lifetime
   - Export as CSV and attach to the report

3. **Report:**
   - The exact `[POC] Child exit code:` line from stdout
   - The ProcMon CSV (or a screenshot of the relevant rows)
   - Whether `whoami /groups` was visible before the child exited

---

## Cross-References

- **RESEARCH.md §6 (PoC scope and expected outcomes):**
  `.planning/quick/260508-lqh-scope-phase-31-broker-process-implementa/RESEARCH.md`
  Section "6. Simplest Demonstrable Proof-of-Concept"

- **RESEARCH.md §Assumptions Log A1 (the assumption this PoC validates):**
  Same file, section "Assumptions Log", row A1 —
  "KernelBase's `ConClntInitialize` skips the CSRSS ALPC connect when the child inherits
  the parent's console (no CREATE_NEW_CONSOLE flag)"

- **RESEARCH.md §1b (mechanism viability analysis for console inherit path):**
  Same file, section "1b. Does the Low-IL child inherit the broker's already-attached console?"

- **RESEARCH.md §8 (decision matrix — full Phase 31 vs alternatives):**
  Same file, section "8. Decision Matrix" — use this table once the field result is known

- **Phase 30 field evidence:**
  `.planning/phases/30-windows-nono-shell-architecture/30-WAVE-2-PROCMON.md`
