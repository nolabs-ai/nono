# Phase 31 Scoping: Broker-Process Pattern for `nono shell` on Windows

**Researched:** 2026-05-08
**Domain:** Windows Mandatory Integrity Control, ConPTY broker architecture, CSRSS ALPC port access
**Confidence:** HIGH (mechanism documented by Microsoft and independently verified via multiple sources); MEDIUM (PoC scope estimate, effort decomposition); LOW (specific CSRSS IL inheritance skip behavior — no direct Microsoft documentation found)

---

## Executive Summary

Phase 30 confirmed that `nono shell` on Windows is structurally broken at user-mode for any token shape that forces a Low-IL console-subsystem process to perform an ALPC connection to the CSRSS console port. The CSRSS console port DACL excludes Low-IL clients; `KernelBase!ConClntInitialize` returns `STATUS_ACCESS_DENIED`; the loader sets `STATUS_DLL_INIT_FAILED (0xC0000142)` and the process exits before reaching `main()`.

The broker-process pattern (option 6b) avoids this by having a Medium-IL intermediary binary attach to the console FIRST, then lower its own IL via `SetTokenInformation(TokenIntegrityLevel, Low)`, then spawn the actual shell as a child. The key question this scoping research answers is: **does the spawned Low-IL child actually skip the CSRSS console attach because the broker already holds the console attachment?**

**Finding:** The documented answer is **uncertain but plausible**. Microsoft's `CreateLowProcess` canonical sample shows the straightforward pattern (duplicate token, set IL, `CreateProcessAsUser`). The Microsoft Q&A thread on "CreatePseudoConsole with reduced integrity level" confirms a user shipped a broker that solved their cross-IL ConPTY problem. However, no authoritative documentation directly states that the Low-IL child inherits the already-attached console without retriggering `ConClntInitialize`. This is the core empirical risk that a ~50-line PoC must resolve before committing to full Phase 31.

**Effort estimate:** 6-8 working days if the PoC PoC passes on the first try; 9-12 days if there is a second failure mode to investigate. The PoC itself is ~1.5 days.

**Primary recommendation:** Build the 50-line PoC first (1-2 days). If it succeeds — Low-IL PowerShell survives KernelBase DllMain and produces a prompt — commit to Phase 31 (~7 days net). If it fails, the evidence from the PoC will surface the next failure mode with a ProcMon trace, potentially pointing at AppContainer (6a) as the only viable user-mode alternative.

---

## 1. Mechanism Viability

### 1a. SetTokenInformation(TokenIntegrityLevel, Low) on a running token — does it work?

**VERIFIED [CITED: learn.microsoft.com/SetTokenInformation, TOKEN_INFORMATION_CLASS]:**

`SetTokenInformation` with `TokenIntegrityLevel` is explicitly supported for lowering the integrity level of an access token. The canonical Microsoft code sample in "Designing Applications to Run at a Low Integrity Level" demonstrates exactly this:

1. `OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | ..., &hToken)`
2. `DuplicateTokenEx(hToken, ..., TokenPrimary, &hNewToken)`
3. `SetTokenInformation(hNewToken, TokenIntegrityLevel, &tml, ...)`
4. `CreateProcessAsUser(hNewToken, NULL, wszProcessName, ...)`

The broker-then-self-degrade pattern is subtly different: the broker process is already running at Medium IL. It duplicates its OWN token, lowers IL on the duplicate, then passes the duplicate to `CreateProcessAsUserW` for the child. The broker itself stays at Medium IL — only the child gets the Low-IL token. This is correct and is what nono's `create_low_integrity_primary_token()` already does, just called from the broker rather than from `nono.exe` directly.

**CITED [Microsoft MSDN, "Designing Applications to Run at a Low Integrity Level", 2007]:**
URL: https://learn.microsoft.com/en-us/previous-versions/dotnet/articles/bb625960(v=msdn.10)

**Gotcha — UIPI:** Microsoft's `SetTokenInformation` docs note that if a THREAD token (not process token) IL is set, UIPI does not change retroactively. For the broker, this does not apply because the broker is setting the IL on a NEW token that will be used for a NEW process, not changing its own thread token post-startup.

### 1b. Does the Low-IL child inherit the broker's already-attached console?

**ASSUMED — core empirical uncertainty.**

Windows documentation establishes that when a child process is created WITHOUT `CREATE_NEW_CONSOLE` or `DETACHED_PROCESS` flags, and the parent has a console, the child inherits it. `KernelBase!BaseDllInitialize → ConClntInitialize` is documented to connect a process to the console subsystem during DllMain. The question is whether `ConClntInitialize` checks "do I already have a console handle from the parent?" and skips the CSRSS ALPC port connection if so.

**Evidence for** (the key insight from Phase 30 analysis, unverified in this session):
- The Phase 30 WAVE-2-PROCMON.md states: "the child INHERITS the already-attached console (KernelBase's DllMain skips CSRSS attach when a console is inherited)." This matches the general Windows console inheritance documentation which says that if a parent has a console and no console-creation flag is specified, the child uses that console.
- In the modern Windows console model (Win8+), `conhost.exe` is a child of the console-allocating process. If the broker attaches to CSRSS at Medium IL and spawns `conhost.exe`, the Low-IL child would inherit `conhost`'s handles — `ConClntInitialize` might complete by connecting to the existing `conhost.exe` rather than by connecting to CSRSS's port, depending on how ConPTY modifies this path.
- The Microsoft Q&A "CreatePseudoConsole with reduced integrity level" thread (URL: https://learn.microsoft.com/en-us/answers/questions/1040676/createpseudoconsole-with-reduced-integrity-level) confirms: a user implemented this broker pattern and reported "I created the broker process and it solved the problem." The context was a SYSTEM→Medium→Low chain, where Medium is the broker creating the ConPTY and spawning the Low child.

**Evidence against / complications:**
- The same Phase 30 analysis established that `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` causes KernelBase to STILL call `ConClntInitialize` even when the parent has a console — the pseudoconsole is a separate handle path. If the broker uses `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` when spawning the Low-IL child, the Low-IL child will still attempt CSRSS attach.
- The broker pattern might work if the broker spawns the Low-IL child WITHOUT `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` — instead relying on plain console inheritance. But the broker itself must be attached to the ConPTY (which was allocated by `nono.exe` upstream) for terminal I/O to flow.

**Verdict:** The mechanism is plausible but has one unresolved question: whether the Low-IL child should be spawned with or without `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`, and which case succeeds. The PoC (Section 6) tests exactly this.

### 1c. Mandatory-label NO_WRITE_UP enforcement

**VERIFIED [CITED: Microsoft, Mandatory Integrity Control overview]:**

A Low-IL process subject accessing a Medium-IL object (e.g., user's Desktop folder) fails the mandatory pre-DACL integrity check. `TOKEN_MANDATORY_NO_WRITE_UP` is set by default on all tokens. This enforcement is at kernel level, independent of which process created the child. The broker pattern does not weaken this — it only changes HOW the Low-IL child is created, not what its token looks like.

`nono`'s existing `try_set_mandatory_label` / `AppliedLabelsGuard` mechanism is unaffected. It operates on file SACLs and is orthogonal to process-creation mechanism.

---

## 2. Reference Implementations

### 2a. Microsoft canonical pattern

**CITED: "Designing Applications to Run at a Low Integrity Level" (Microsoft MSDN, archived 2007)**
URL: https://learn.microsoft.com/en-us/previous-versions/dotnet/articles/bb625960(v=msdn.10)

The `CreateLowProcess()` sample function is the canonical reference. It uses:
- `OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hToken)`
- `DuplicateTokenEx(hToken, 0, NULL, SecurityImpersonation, TokenPrimary, &hNewToken)`
- `SetTokenInformation(hNewToken, TokenIntegrityLevel, &TIL, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pIntegritySid))`
- `CreateProcessAsUser(hNewToken, NULL, wszProcessName, NULL, NULL, FALSE, 0, NULL, NULL, &StartupInfo, &ProcInfo)`

This is essentially what nono's `create_low_integrity_primary_token()` already does, just called from inside `nono.exe`. The broker moves the call to a separate binary.

### 2b. Chromium sandbox broker/target architecture

**CITED: Chromium Sandbox documentation**
URL: https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md
URL: https://searchfox.org/firefox-main/source/security/sandbox/chromium/sandbox/win/src/security_level.h

Chromium's broker (browser process) runs at Medium IL. Renderer processes run at Untrusted IL (S-1-16-0). GPU processes run at Low IL (S-1-16-4096). The broker spawns targets; targets do not spawn the broker. Critically, Chromium renderer processes are NOT console-subsystem applications — they use redirected stdio and custom IPC, so they never trigger `ConClntInitialize`. This means Chromium's architecture does NOT directly validate the broker pattern for console-subsystem children (PowerShell / cmd.exe).

The Chromium architecture is cited as a "related" pattern, not a direct precedent for console-subsystem broker.

### 2c. Microsoft Q&A: ConPTY with reduced integrity level

**CITED: Microsoft Learn Q&A, 2022**
URL: https://learn.microsoft.com/en-us/answers/questions/1040676/createpseudoconsole-with-reduced-integrity-level

A developer had a SYSTEM process needing to spawn a Low-IL child with ConPTY. The thread identifies:
- The ConPTY (`HPCON`) cannot be duplicated — its lifetime is tied to the allocating process.
- `CreateProcessAsUserW` is the only one of the three user-token CreateProcess functions that accepts `EXTENDED_STARTUPINFO_PRESENT` (and thus `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE`).
- The broker pattern was confirmed to work in the poster's SYSTEM→Medium→Low chain.

**Limitation:** The exact token shape and console-creation flags used by the poster are not documented. The PoC fills this gap.

### 2d. Project Zero: "In-Console-Able" (CSRSS ALPC and IL)

**CITED: Google Project Zero blog, May 2015**
URL: https://googleprojectzero.blogspot.com/2015/05/in-console-able.html

Confirms that `AllocConsole` from a low-integrity process hits `STATUS_ACCESS_DENIED` because `conhost.exe`, when spawned by the console driver, cannot open the Low-IL parent process to set up the server-side console attachment. This is a DIFFERENT failure mode from the one Phase 30 observed (which was the client-side `NtAlpcConnectPort` from `ConClntInitialize` inside the child's DllMain). Both failure modes exist; Phase 30's is the client-side one. The broker pattern addresses the client-side failure by ensuring the console attachment happens at Medium IL.

---

## 3. Implementation Shape Estimate

### 3a. New binary: `nono-shell-broker`

**Location in workspace:** `crates/nono-shell-broker/` as a new Cargo workspace member. Rationale: it is a standalone binary with Windows-only Win32 FFI dependencies; keeping it in `crates/` is consistent with the existing workspace structure (`crates/nono`, `crates/nono-cli`, `crates/nono-proxy`).

**`Cargo.toml` changes (workspace root):** Add `"crates/nono-shell-broker"` to `[workspace] members`. The new crate depends on `windows-sys` (already in the workspace transitively via `nono-cli`) and `nono` (for `CapabilitySet` deserialization). It does NOT depend on `nono-cli` to avoid circular crate structure.

**Estimated size:** ~200-350 LOC for `main.rs` covering:
- Argument parsing (receive shell path, ConPTY pipe handles, CapabilitySet JSON) — ~40 LOC
- Console attachment at Medium IL — ~20 LOC  
- Token IL self-degradation via `create_low_integrity_primary_token()` (copy of existing function or shared via `nono` lib) — ~50 LOC
- `CreateProcessAsUserW` with Low-IL token and appropriate console flags — ~60 LOC
- Wait for child + forward exit code — ~20 LOC
- Error handling (`NonoError` propagation, no `.unwrap()`, no `.expect()`) — ~50 LOC overhead

**Shared code question:** `create_low_integrity_primary_token()` is currently `pub(super)` in `crates/nono-cli/src/exec_strategy_windows/launch.rs`. For the broker to use it, it must either:
- (a) Be moved to `crates/nono/src/sandbox/windows.rs` as a library function (preferred — avoids code duplication), or
- (b) Be duplicated into the broker crate (simpler short-term, creates drift risk).
This is a D-decision for Phase 31 — research recommends option (a) since `try_set_mandatory_label` already lives in the library.

### 3b. Changes in `launch.rs`

A new cascade arm replaces the existing `WindowsTokenArm::LowIlPrimary` arm for PTY launches. Instead of calling `create_low_integrity_primary_token()` and then `CreateProcessAsUserW(h_token, powershell.exe, ...)` directly, the arm calls the broker binary via `CreateProcessW(broker.exe, args_including_handles_and_shell_path)`.

**Token arm changes:**
- `WindowsTokenArm::LowIlPrimary` stays for the non-PTY cases (legacy Direct path).
- A new variant `WindowsTokenArm::BrokerLaunch` is added for the PTY+supervised case.
- `select_windows_token_arm()` adds one branch: if `has_pty && !is_detached`, return `BrokerLaunch`.

**Handle passing to broker:** The broker needs:
1. The ConPTY `HPCON` — but as noted in Section 2c, `HPCON` cannot be duplicated. This means `nono.exe` must pass the raw pipe handles that `HPCON` is built from, and the BROKER must call `CreatePseudoConsole(...)` itself using those handles. This changes the ConPTY allocation site: `pty_proxy::open_pty()` in `nono.exe` must be restructured so that the raw pipe ends can be passed to the broker. This is non-trivial and is the primary architectural complication.

**Alternative:** `nono.exe` allocates the ConPTY normally, but instead of spawning PowerShell itself, it spawns the broker as a Medium-IL process with `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` pointing to the existing HPCON. The broker inherits the ConPTY channel from `nono.exe` and can attach CSRSS using it (at Medium IL), then spawn the Low-IL PowerShell child. This approach keeps `pty_proxy::open_pty()` unchanged.

**Recommended shape for Phase 31 planning:** Second alternative (broker inherits HPCON from `nono.exe`, broker attaches console at Medium IL, broker spawns Low-IL child). This minimizes `pty_proxy` changes.

**Config serialization to broker:** The broker needs to know which shell binary to launch. This can be passed as command-line arguments. CapabilitySet and profile data are NOT needed by the broker — those are applied via `try_set_mandatory_label` by the supervisor BEFORE the broker is spawned.

### 3c. Capability pipe SDDL

The existing capability pipe SDDL (commit `938887f`) was verified by Phase 30 research to admit Low-IL primary token clients. The broker does not change this — the broker itself is Medium-IL and has no problem accessing the capability pipe. The Low-IL PowerShell child talks to `nono.exe` only through the ConPTY terminal channel, not through the capability pipe. No SDDL changes needed.

### 3d. Supervision model

The broker binary is a short-lived intermediary. Once it has created the Low-IL PowerShell child, it must either:
- (a) Wait for the child to exit and forward its exit code back to `nono.exe` (via the broker's own exit code or via an IPC pipe), or
- (b) `NtSuspendProcess` the child, signal `nono.exe`, let `nono.exe` take over child supervision, then exit.

Option (a) is simpler: the broker becomes the immediate parent of the Low-IL child, waits for it, and exits with the child's exit code. `nono.exe` monitors the broker's exit code to detect child failure. This means `nono.exe`'s `WindowsSupervisedChild` structure needs a minor adjustment — it monitors the broker PID rather than the shell PID directly.

---

## 4. Threat Model Considerations

### 4a. Broker attack surface

The broker runs at Medium IL and has:
- A handle to the ConPTY channel (inherited from `nono.exe`)
- The ability to spawn a Low-IL child
- No access to the CapabilitySet or sandbox policy (not passed to broker)

The broker does NOT hold a Medium-IL token that it passes to the child — it creates a new Low-IL duplicate token. A compromise of the broker via an exploit in the broker's own code would give the attacker Medium-IL access. However, the broker's code is minimal (no parsing, no network, no external input beyond argv), so its attack surface is small.

### 4b. Handle leak risk

The broker inherits the ConPTY pipe handles from `nono.exe`. If those handles are marked inheritable, the Low-IL PowerShell child would also inherit them — creating a handle leak if the child has more handles than it should. Mitigation: `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` restricts which handles the Low-IL child inherits, limiting it to only the ConPTY attribute list handles. This is already the standard practice for ConPTY process creation.

### 4c. Broker IPC trust boundary

The Low-IL child sends terminal I/O through the ConPTY channel to `nono.exe`. If the Low-IL child is compromised, it can only write data to the terminal buffer — it cannot write back to the broker process (the broker has already finished creating the child and is just waiting for it to exit). No IPC channel from Low-IL child to broker is established.

### 4d. Job Object containment

Phase 30's `AssignProcessToJobObject` call in `nono.exe` must include the broker's PID in the Job Object so the broker's children are also contained. Standard behavior: processes created by a Job Object member are automatically added to the Job Object. The Low-IL PowerShell child (created by the broker) will be in the same Job Object, assuming the Job Object is created before the broker is spawned. Verify: `JOBOBJECT_EXTENDED_LIMIT_INFORMATION.LimitFlags` must NOT include `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK` or `JOB_OBJECT_LIMIT_BREAKAWAY_OK` on the nono Job Object.

**Reusable phase patterns:**
- Phase 18's capability pipe SACL (Low-IL write) pattern — already in place.
- Phase 21's mandatory-label ownership-skip guard — unchanged.
- The RAII `_low_integrity_holder` pattern in `launch.rs` to prevent double-close — the broker binary should use the same pattern.

---

## 5. Effort Estimate

| Task | Days |
|------|------|
| PoC binary (50-line Rust binary that attempts the sequence and prints pass/fail) | 1.5 |
| Field test PoC on Windows test box (may require ProcMon if PoC fails) | 0.5 |
| `crates/nono-shell-broker/` crate scaffolding + workspace integration | 0.5 |
| `main.rs` full implementation (arg parsing, token duplicate, ConPTY attach, spawn Low-IL child, wait + forward exit) | 1.5 |
| `launch.rs` cascade arm extension (`BrokerLaunch` variant, dispatch to broker binary path) | 0.5 |
| Handle passing / ConPTY inheritance wiring (`pty_proxy` minimal changes or none if broker inherits HPCON) | 1.0 |
| Write-deny harness fix (rewrite `Out-File` → `Set-Content` per Wave-2-PROCMON note) + field smoke | 0.5 |
| Threat model review + SECURITY.md annotation | 0.5 |
| Code review, tests (token arm truth-table for BrokerLaunch), bookkeeping | 0.5 |
| **Total (PoC passes first try)** | **7.0** |
| **Contingency (second failure mode to diagnose, additional ProcMon day)** | +2.0 |
| **Realistic range** | **7-9 days** |

**Honest caveat:** The 1.0-day "ConPTY inheritance wiring" estimate could expand to 2-3 days if the broker pattern requires restructuring `pty_proxy::open_pty()` to separate pipe allocation from `CreatePseudoConsole`. The alternative (broker inherits `HPCON` from `nono.exe`) avoids this but requires verifying that `HPCON` lifetime is valid across the parent→broker process boundary — an undocumented property of `HPCON`.

---

## 6. Simplest Demonstrable Proof-of-Concept

### PoC scope

A standalone ~80-100 line Rust binary (`poc-broker-console.rs` or similar) that:

1. Calls `AllocConsole()` to attach to a console at the calling process's IL (Medium if invoked from PowerShell/cmd).
2. Duplicates its own process token.
3. Calls `SetTokenInformation(hNewToken, TokenIntegrityLevel, ...)` to lower the duplicate to Low IL.
4. Calls `CreateProcessAsUserW(hNewToken, "powershell.exe", "-NoLogo", NULL, NULL, 0 /* no CREATE_NEW_CONSOLE */, ...)`.
5. Waits for child exit.
6. Prints `[POC] Child exit code: {code}` and exits.

**Expected outcome (PoC passes):** PowerShell opens at Low IL, prints its banner, waits for input, exits cleanly when `exit` is typed. Exit code 0.

**Expected outcome (PoC fails, variant A):** PowerShell exits with `0xC0000142` — the console attach at Low IL is STILL triggering CSRSS denial even when the parent has a console. This would mean the broker pattern is not viable without PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE changes or AppContainer.

**Expected outcome (PoC fails, variant B):** PowerShell exits with a different NTSTATUS — a new failure mode that ProcMon can localize.

### ConPTY variant

Once the plain-console PoC passes, a second variant adds:
- Parent calls `CreatePseudoConsole(...)` to allocate HPCON.
- Parent spawns PowerShell with `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` pointing to the HPCON.
- Checks whether Low-IL PowerShell still survives.

This variant resolves the critical question about whether `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` in the broker's `CreateProcessAsUserW` call re-triggers `ConClntInitialize` at Low IL.

### When to build it

BEFORE committing to Phase 31 planning. The PoC can be built in a `playground/` scratch directory or as a `crates/nono-poc-broker/` temporary crate (excluded from workspace via `exclude = [...]` or just never merged). If the PoC passes, delete it and proceed to Phase 31. If it fails, capture the ProcMon trace as Phase 31's primary research artifact.

---

## 7. Alternative Approaches

### 7a. AppContainer (option 6a)

Replace the token-manipulation approach entirely with an AppContainer (LOWBOX token + package SID + capability SIDs). AppContainer processes get their own CSRSS console handler that accepts AppContainer clients — the IL mismatch problem disappears structurally.

**Trade-off:** AppContainer is a much larger surface area. Spawning a PowerShell or cmd.exe AppContainer process requires an AppContainer profile (created via `CreateAppContainerProfile`), specifying capability SIDs for every Windows resource the shell needs (filesystem, network, registry, COM), and ACL-ing those resources with the package SID. PowerShell 5.1 is not tested or supported in AppContainer. Empirically, legacy console apps break in AppContainer because their dependencies (CLR, COM, registry access) are blocked by capability gates. Estimated effort: 2-3 weeks including compatibility debugging, far exceeding the broker pattern. The Phase 30 analysis rated it at "1-2 weeks" which likely underestimates PowerShell-specific compat work.

**Recommendation:** Do not pursue AppContainer for Phase 31 unless the broker PoC fails AND there is no viable alternative.

### 7b. Skip TUI, use stdin-redirected non-interactive PowerShell

Use anonymous-pipe stdio (Phase 17's pattern) instead of ConPTY. PowerShell at Low IL with stdin/stdout as pipes should succeed — no console-subsystem CSRSS attach triggered. Claude Code would run without TUI (no alternate screen buffer, no cursor positioning, no raw-mode input).

**Trade-off:** Phase 30 CONTEXT D-05 explicitly locked TUI rendering as a Phase 30 acceptance criterion. For Phase 31, this would require re-discussing the acceptance criteria. Claude Code without TUI is a degraded experience — it switches to a text-only mode that is significantly less capable. This option sidesteps the technical problem by removing the requirement, not by solving it. Acceptable for `nono run -- claude` non-interactive flows (already working), but not for `nono shell`'s stated purpose.

**Recommendation:** Not appropriate for Phase 31 as currently scoped. Could be documented as a permanent fallback for situations where the broker approach fails on specific Windows configurations.

### 7c. Move the demo to Linux/macOS

`nono shell` on Linux with Landlock and on macOS with Seatbelt uses entirely different enforcement mechanisms (not CSRSS, not Mandatory Integrity Control). There is no reason to believe it has an analogous failure mode. A demo of `nono shell` on Linux/macOS with Claude TUI running inside Landlock/Seatbelt enforcement would demonstrate the core value proposition.

**Trade-off:** The Windows market (enterprise customers, Windows-native AI agent deployments) is not served. The demo covers Linux/macOS developers but not Windows practitioners. This is a positioning choice, not a technical limitation — the Linux/macOS path is presumably working now (though it should be smoke-tested before the demo to confirm). Zero new code required if confirmed working.

**Recommendation:** Run the Linux/macOS smoke test immediately (one day of effort). Use the result as the demo fallback while Phase 31 broker work proceeds. If Phase 31 slips or fails, the Linux/macOS demo ships as the v3.0 preview.

### 7d. `nono run` non-TUI on Windows + `nono shell` on Linux/macOS

Document the platform capability matrix honestly:
- Windows: `nono run -- claude --version` (non-TUI, works today)
- Linux/macOS: `nono shell --profile claude-code` (TUI, pending smoke test)

This is the current reality after Phase 30's failure-path shipment. The cookbook already documents it this way. No Phase 31 work required for the demo itself — the demo just shows different features on different platforms.

**Trade-off:** Sophisticated users may notice the Windows gap and wonder if the product is production-ready on Windows. For v3.0 / v2.3 positioning, this is a known limitation with a documented timeline for resolution. The honest framing is defensible.

**Recommendation:** This is the zero-new-code option. Use it as the demo floor while Phase 31 is evaluated. If the Phase 31 PoC succeeds, upgrade the demo.

---

## 8. Decision Matrix

| Option | Effort (days) | Demo Timing | Security Completeness | Windows Coverage |
|--------|--------------|-------------|----------------------|-----------------|
| **Phase 31: Broker pattern** | 7-9 (excl. PoC) + 1.5 PoC | 4-5 weeks from today if Phase 31 starts now | HIGH — Low-IL child with NO_WRITE_UP mandatory label enforcement; broker is minimal and auditable | FULL — Windows 10/11, PowerShell 5.1 / cmd.exe, ConPTY TUI |
| **6a: AppContainer** | 15-25 | 6-10 weeks | HIGHEST — AppContainer is a security boundary; mandatory-label + capability gates | FULL — but PowerShell 5.1 compat risk is unresolved |
| **7b: Pipe stdio (no TUI)** | 0-1 (descope only) | Immediate | MEDIUM — write-deny enforcement preserved, but lose ConPTY attack surface reduction; shell is usable for scripts but not TUI agents | PARTIAL — Windows works but experience is degraded |
| **7c: Linux/macOS demo** | 0.5 (smoke test only) | Immediate | HIGH (for Linux/macOS) — Landlock/Seatbelt enforcement is feature-complete | NONE — Windows demo remains `nono run` non-TUI |
| **7d: Multi-platform honest demo** | 0 | Immediate | HIGH on Linux/macOS, MEDIUM on Windows | PARTIAL — Windows shows non-TUI path |
| **6e: v3.0 kernel mini-filter** | 30+ | v3.0 (months) | HIGHEST — kernel enforcement; can express deny within allow on Windows | FULL — but requires significant additional engineering |

**Scoring notes:**
- "Demo Timing" counts from today (2026-05-08) assuming Phase 31 work starts this week.
- "Security Completeness" for broker pattern is HIGH but explicitly does NOT include WFP per-session network differentiation (waived, same as Phase 15 detached path).
- "Windows Coverage" for 7c/7d is NONE for the TUI shell story, but non-zero for non-TUI `nono run` usage.

**Recommended decision path:**

1. **Today → Day 1.5:** Build and run the PoC (Section 6). Cost: 1.5 days. Risk: low (even a failing PoC produces valuable evidence).
2. **If PoC passes:** Commit to Phase 31 using this research as the scoping input. Total Phase 31 effort: ~7 days.
3. **If PoC fails (variant A):** The broker pattern is not viable without AppContainer. Escalate to discuss-phase for the 6a vs 7c vs 7d decision. Do NOT start full Phase 31 implementation.
4. **While Phase 31 is in progress OR if it is deferred:** Ship the Linux/macOS smoke test (7c) as the demo vehicle. Cost: 0.5 days.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | KernelBase's `ConClntInitialize` skips the CSRSS ALPC connect when the child inherits the parent's console (no CREATE_NEW_CONSOLE flag) | 1b, 6 | High — this is the core broker mechanism assumption; if false, the broker pattern fails and we need AppContainer or defer |
| A2 | `HPCON` handle remains valid in the broker process if inherited from `nono.exe` and used in `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` by the broker | 3b | Medium — if false, requires restructuring `pty_proxy::open_pty()` to separate pipe allocation from `CreatePseudoConsole`; adds ~1.5 days |
| A3 | PowerShell 5.1 with an inherited console (no ConPTY) can still support Claude Code's TUI requirements (alternate screen buffer, raw mode) | 3b | Medium — if false, the ConPTY variant (broker passes HPCON to Low-IL child) is required, which depends on A1 being true |
| A4 | The broker pattern's user (Microsoft Q&A 2022) was in a Windows 10/11 context, not a legacy Windows version | 2c | Low — the thread is from 2022; Windows 10/11 is the target environment |
| A5 | `Job Object` containment automatically includes the Low-IL PowerShell child (grandchild of `nono.exe`) without explicit `AssignProcessToJobObject` call | 4d | Medium — if `JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK` is inadvertently set, the child escapes the Job Object |

---

## Open Questions

1. **Does `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` in the broker's `CreateProcessAsUserW` call retrigger `ConClntInitialize` for the Low-IL child?**
   - What we know: Phase 30 confirms that ConPTY attributes do not bypass CSRSS ALPC attach.
   - What's unclear: Whether passing ConPTY through the broker (which has CSRSS already attached at Medium IL) changes the child's initialization path.
   - Recommendation: PoC variant 2 (Section 6) answers this directly.

2. **Where should `create_low_integrity_primary_token()` live in the workspace?**
   - What we know: Currently `pub(super)` in `nono-cli` launch.rs; the broker binary can't use it as-is.
   - What's unclear: Whether the function belongs in `nono` library vs duplicated in broker vs extracted to a `nono-windows-tokens` internal crate.
   - Recommendation: Move to `crates/nono/src/sandbox/windows.rs` alongside `try_set_mandatory_label`. Requires a Phase 31 Plan 1 task.

3. **Is the ConPTY write-deny harness fix required before Phase 31 can claim Acceptance #3?**
   - What we know: `30-WAVE-2-PROCMON.md` documents the `Out-File` PowerShell invalid-syntax bug that causes the harness to always exit 42 (PASS). The fix is `Set-Content -Path -Value`.
   - Recommendation: Fix as Phase 31 Wave 0 task (not optional). This is a blocking harness correctness bug, not a new feature.

---

## Sources

### Primary (HIGH confidence)
- Microsoft Learn: SetTokenInformation — https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-settokeninformation
- Microsoft Learn: TOKEN_INFORMATION_CLASS — https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
- Microsoft MSDN: "Designing Applications to Run at a Low Integrity Level" — https://learn.microsoft.com/en-us/previous-versions/dotnet/articles/bb625960(v=msdn.10) (canonical broker+IL sample code)
- Chromium Sandbox documentation — https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md
- Chromium security_level.h (Firefox mirror) — https://searchfox.org/firefox-main/source/security/sandbox/chromium/sandbox/win/src/security_level.h
- `crates/nono-cli/src/exec_strategy_windows/launch.rs` (lines 1024-1349) — existing implementation; verified by reading source
- `.planning/phases/30-windows-nono-shell-architecture/30-WAVE-2-PROCMON.md` — Phase 30 field evidence; primary failure-mode documentation

### Secondary (MEDIUM confidence)
- Microsoft Q&A: "CreatePseudoConsole with reduced integrity level" (2022) — https://learn.microsoft.com/en-us/answers/questions/1040676/createpseudoconsole-with-reduced-integrity-level (user-confirmed broker pattern works)
- Google Project Zero: "In-Console-Able" (2015) — https://googleprojectzero.blogspot.com/2015/05/in-console-able.html (CSRSS + Low IL console failure mode analysis)
- GitHub: rprichard/win32-console-docs — https://github.com/rprichard/win32-console-docs (console handle inheritance semantics)
- GitHub: microsoft/terminal issue #5468 — https://github.com/microsoft/terminal/issues/5468 (cross-IL console operation denial; Resolution-By-Design)
- CSRSS write-up: j00ru//vx tech blog — https://j00ru.vexillium.org/2010/07/windows-csrss-write-up-inter-process-communication-part-1/
- ikriv.com: "Exact meaning of console creation flags" — https://ikriv.com/dev/cpp/ConsoleProxy/flags (console flag inheritance rules)
- `.planning/debug/resolved/nono-shell-status-dll-init-failed.md` — debug session with full call graph trace

### Tertiary (LOW confidence)
- Web searches for "ConClntInitialize console inherit skip CSRSS attach" — no direct documentation found; mechanism inferred from first principles and blog cross-references.
