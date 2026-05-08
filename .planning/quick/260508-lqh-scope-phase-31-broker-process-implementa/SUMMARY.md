---
quick_id: 260508-lqh
slug: scope-phase-31-broker-process-implementa
description: scope Phase 31 broker-process implementation
date: 2026-05-08
status: complete
mode: research-only
duration: ~30 min (research agent run + summary writeup)
output_artifacts:
  - .planning/quick/260508-lqh-scope-phase-31-broker-process-implementa/RESEARCH.md
---

# Quick Task: Scope Phase 31 broker-process implementation

**Mode:** `--research` (no implementation; scoping output only)

**Research artifact:** `.planning/quick/260508-lqh-scope-phase-31-broker-process-implementa/RESEARCH.md` (370 lines, 8 sections + decision matrix + assumptions log)

## Headline findings

1. **Mechanism is HIGH-confidence documented and confirmed working in at least one real deployment.** Microsoft's Q&A thread on "CreatePseudoConsole with reduced integrity level" (2022) has a user confirming "I created the broker process and it solved the problem" for SYSTEM→Medium→Low chain. `SetTokenInformation(TokenIntegrityLevel, Low)` on a duplicated token before `CreateProcessAsUserW` is the canonical Microsoft-documented pattern.

2. **Core empirical risk is whether the Low-IL child SKIPS the CSRSS ALPC attach** when inheriting the broker's already-attached console. Phase 30 analysis asserts this skip happens, but it's not directly confirmed by Microsoft documentation. **A 50-100 line Rust PoC (~1.5 days) resolves this before committing to full Phase 31** — this is the de-risking step.

3. **ConPTY complications are real.** `HPCON` cannot be duplicated. Two paths: (a) broker inherits HPCON from `nono.exe` (simpler, undocumented HPCON cross-process lifetime), or (b) `nono.exe` passes raw pipes and broker calls `CreatePseudoConsole` itself (more complex, requires `pty_proxy` restructuring). PoC de-risks both.

4. **Field-smoke harness bug must be fixed before any write-deny acceptance claim.** `Out-File '<path>' '<content>'` syntax in `scripts/test-windows-shell-write-deny.ps1` is invalid PowerShell — throws `ParameterBindingValidationException` immediately, causing harness to always report PASS regardless of OS enforcement. **Fix:** `Set-Content -Path '<path>' -Value '<content>'`. **Phase 31 Wave 0 blocker** (already documented in 30-WAVE-2-PROCMON.md "Critical caveat for Phase 31 inheritance" section).

5. **Honest effort estimate: 7-9 working days** (after PoC confirms viability). Decomposition: 1.5 days PoC, 0.5 crate scaffolding, 1.5 main.rs, 1.0 ConPTY wiring, 0.5 launch.rs cascade arm, 0.5 harness fix + field smoke, 0.5 threat model, 0.5 code review/tests/bookkeeping. NOT "1 week of handwaving" — actual decomposition with realistic per-task day counts.

## Decision matrix (excerpted from RESEARCH.md §8)

| Option | Effort (days) | Demo Timing | Security | Windows Coverage |
|---|---|---|---|---|
| **Phase 31: Broker pattern** | 7-9 (+1.5 PoC) | 4-5 weeks | HIGH | FULL Windows TUI |
| **6a: AppContainer** | 15-25 | 6-10 weeks | HIGHEST | PS 5.1 compat risk |
| **7b: Pipe stdio (no TUI)** | 0-1 (descope) | Immediate | MEDIUM | partial — degraded UX |
| **7c: Linux/macOS demo** | 0.5 (smoke test) | Immediate | HIGH | NONE on Windows |
| **7d: Multi-platform honest demo** | 0 | Immediate | mixed | partial — `nono run` only on Windows |
| **6e: v3.0 kernel filter** | 30+ | months | HIGHEST | FULL |

## Recommended decision path (from RESEARCH.md)

1. **Today → Day 1.5:** Build and run the PoC. Cost: 1.5 days. Risk: low (even a failing PoC produces valuable evidence).
2. **If PoC passes:** Commit to Phase 31 using this research as scoping input. Total: ~7 more days.
3. **If PoC fails:** Broker pattern not viable; escalate to `/gsd-discuss-phase` for 6a vs 7c vs 7d decision.
4. **While Phase 31 is in progress OR if deferred:** Ship the Linux/macOS smoke test (7c) as immediate demo vehicle. Cost: 0.5 days.

## Open questions for the user

1. **Build the PoC first, or commit to Phase 31 planning immediately?** RESEARCH.md recommends PoC first.
2. **Where should `create_low_integrity_primary_token()` live?** Currently `pub(super)` in `nono-cli`. Moving to `nono` lib is cleaner but requires a library-boundary D-decision.
3. **Demo strategy while Phase 31 is in flight?** Recommend Linux/macOS smoke test immediately as the parallel demo vehicle.

## Key sources cited (from RESEARCH.md §Sources)

**HIGH confidence:**
- Microsoft Q&A: "CreatePseudoConsole with reduced integrity level" (2022) — direct confirmation of broker pattern working
- Microsoft Win32 docs: `SetTokenInformation`, `DuplicateTokenEx`, `CreateProcessAsUserW`, `CreatePseudoConsole`
- Microsoft mandatory-integrity-control documentation (NO_WRITE_UP semantics)

**MEDIUM confidence:**
- Chromium sandbox source — broker/target architecture (more elaborate than what we need; concept overlap)
- Project Zero "In-Console-Able" (CSRSS ALPC and IL behavior at lower level)

**LOW confidence (assumption-only):**
- A1: KernelBase!ConClntInitialize skips CSRSS attach on inherited console (the core broker assumption)
- A2: HPCON inherits valid across process boundary

## What this task did NOT do

- No source code modifications attempted
- No Phase 31 planning artifacts created (no PLAN.md, no CONTEXT.md, no REQUIREMENTS.md additions)
- No PoC implementation
- No web research outside the scoping window (~1 hour)

## Recommended next actions for the user

The user should now decide:

- **Build the PoC** → spawn `/gsd-quick "broker-process PoC: 50-line Rust binary that drops to Low-IL post-startup, inherits console from Medium parent, spawns PowerShell, asserts survival past KernelBase DllMain"` (or invoke as a focused debug session)
- **Commit to Phase 31 immediately** → `/gsd-phase add 31` then `/gsd-discuss-phase 31` using this RESEARCH.md as scoping input
- **Fall back to Linux/macOS demo path** → `/gsd-quick "field-test nono shell on Linux for demo viability"`
- **Multi-platform honest demo** → 0 new code; package what exists with honest framing

This research artifact is the input that makes any of those decisions defensible. No further action required from this quick task.
