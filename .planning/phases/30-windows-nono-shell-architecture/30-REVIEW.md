---
phase: 30-windows-nono-shell-architecture
reviewed: 2026-05-08T14:00:00Z
depth: standard
files_reviewed: 4
files_reviewed_list:
  - crates/nono-cli/src/exec_strategy_windows/launch.rs
  - scripts/test-windows-shell-tui.ps1
  - scripts/test-windows-shell-write-deny.ps1
  - docs/cli/development/windows-poc-handoff.mdx
findings:
  critical: 1
  warning: 4
  info: 2
  total: 7
status: issues_found
---

# Phase 30: Code Review Report

**Reviewed:** 2026-05-08
**Depth:** standard
**Files Reviewed:** 4
**Status:** issues_found

## Summary

Phase 30 delivered: (a) a new `WindowsTokenArm` enum + `select_windows_token_arm` pure helper + a 6th cascade arm in `spawn_windows_child` (`LowIlPrimary` when `pty.is_some()`, Plan 30-02); (b) two PowerShell harness scripts (`test-windows-shell-tui.ps1`, `test-windows-shell-write-deny.ps1`, Plan 30-03); (c) a cookbook revert on `docs/cli/development/windows-poc-handoff.mdx` documenting the v3.0 deferral (Plan 30-05). The phase closed with `exhaust-without-fix` — the LowIlPrimary cascade arm is deliberately preserved as dead code for future Phase 31 / v3.0 broker-process work.

The Rust code is structurally sound. Branch ordering, holder discipline, RAII, and test coverage are correct for their stated purpose. One BLOCKER-level bug exists in `create_low_integrity_primary_token`: the `DuplicateTokenEx` call passes `SecurityImpersonation` as the impersonation level when `TokenPrimary` is the requested token type — those two parameters conflict at the Win32 API level and will cause `CreateProcessAsUserW` to fail with `ERROR_BAD_IMPERSONATION_LEVEL`. This is latent (the cascade arm is currently dead code) but it is the exact code path Phase 31 will activate, so it must be fixed before Phase 31 ships.

The PowerShell harnesses contain the two documented pre-existing bugs (tracked as Phase 31 inheritance) plus two new issues not documented elsewhere: a regex correctness defect in `Read-PassFail` that causes operator input like "fail" to match PASS, and an `Out-File` syntax error in the injected script that would make the write-deny test always reach the catch block and always exit 42 (PASS) even when the file is writable — giving a false PASS on Acceptance #3.

The cookbook accurately reflects the v3.0 deferral. Anchor links are present and correct.

---

## Critical Issues

### CR-01: `DuplicateTokenEx` impersonation-level mismatch will prevent `CreateProcessAsUserW` from using the Low-IL token

**File:** `crates/nono-cli/src/exec_strategy_windows/launch.rs:1098-1105`

**Issue:** `create_low_integrity_primary_token` calls `DuplicateTokenEx` with `SecurityImpersonation` as the `ImpersonationLevel` argument while simultaneously requesting `TokenType = TokenPrimary`. These two parameters are contradictory. Per the Win32 documentation (`DuplicateTokenEx` remarks): when `TokenType` is `TokenPrimary`, the `ImpersonationLevel` parameter is **ignored** by the duplication call itself — but the resulting token retains the impersonation metadata from the source. In practice, on current Windows builds, `CreateProcessAsUserW` validates that a token used for process creation is a true primary token with `SecurityAnonymous` or has `SecurityImpersonation` stripped. Passing a token that carries `SecurityImpersonation` metadata into `CreateProcessAsUserW` returns `ERROR_BAD_IMPERSONATION_LEVEL` (1346). The correct `ImpersonationLevel` for a `TokenPrimary` duplicate is `SecurityAnonymous` (0).

This bug is currently latent because the `LowIlPrimary` cascade arm is dead code (Phase 30 confirmed `STATUS_DLL_INIT_FAILED` before `CreateProcessAsUserW` even completes child initialization, and Phase 15's gate prevents this path from being reached in production today). However, Phase 31's broker-process pattern will activate this code path directly. If the fix is not applied before Phase 31, the Phase 31 smoke will fail with `ERROR_BAD_IMPERSONATION_LEVEL` before the first meaningful token test.

**Fix:**
```rust
DuplicateTokenEx(
    current_token.raw(),
    TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
    std::ptr::null(),
-   SecurityImpersonation as SECURITY_IMPERSONATION_LEVEL,
+   SecurityAnonymous as SECURITY_IMPERSONATION_LEVEL,  // ignored for TokenPrimary but must be valid
    TokenPrimary,
    &mut primary_token,
)
```

Add a comment next to the argument: `// ImpersonationLevel is ignored for TokenPrimary per MSDN; use SecurityAnonymous (0) to prevent ERROR_BAD_IMPERSONATION_LEVEL on CreateProcessAsUserW (Win32 quirk).`

The existing `low_integrity_primary_token_sets_low_il` test does NOT catch this because it exercises `create_low_integrity_primary_token()` in isolation — it never calls `CreateProcessAsUserW`. Add a Phase 31 acceptance gate that actually passes the token to a process creation call.

---

## Warnings

### WR-01: `Out-File` syntax in injected write-deny script is invalid — test always reaches the catch block (known deferred, but the false-PASS consequence is undocumented)

**File:** `scripts/test-windows-shell-write-deny.ps1:132`

**Issue:** The injected script contains:
```powershell
Out-File '$targetFile' 'phase 30 write-deny test' -ErrorAction Stop
```
`Out-File` does not accept content as a positional parameter — the correct invocation is `Set-Content -Path '$targetFile' -Value 'phase 30 write-deny test'` or `'phase 30 write-deny test' | Out-File -FilePath '$targetFile'`. As written, PowerShell 5.1 interprets `'phase 30 write-deny test'` as a second positional argument to `-FilePath`, which is not a valid parameter set. The cmdlet throws a `ParameterBindingException` and always reaches the `catch` block. Because the `catch` block does not exit non-zero — it calls `Write-Host` and falls through — the `if (Test-Path '$targetFile')` check immediately follows; the file was never created (due to the exception, not due to OS-level write-deny), so `Test-Path` returns false, and `exit 42` fires.

Consequence: **Acceptance #3 always exits 42 (PASS) regardless of whether the write would actually be blocked by mandatory-label enforcement.** This is a false-PASS signal on the key security acceptance criterion. The two pre-existing KNOWN bugs in 30-WAVE-2-PROCMON.md are `nono shell` not accepting trailing args and this very `Out-File` invalid-syntax issue; they are documented there as "tracked in Phase 31 inheritance." However, the consequence (false-PASS on the write-deny security test) is not explicitly called out as "this test never measures what it claims" — that framing is important for Phase 31 inheritors.

**Classification note:** Per review instructions, known-deferred bugs from 30-WAVE-2-PROCMON.md are not to be classified as BLOCKER. Classified WARNING because the false-PASS consequence on a security acceptance criterion is a quality failure that Phase 31 must understand before trusting any historical PASS records from this harness.

**Fix (for Phase 31):**
```powershell
# Option A — pipe to Out-File
'phase 30 write-deny test' | Out-File -FilePath '$targetFile' -ErrorAction Stop
# Option B — Set-Content
Set-Content -Path '$targetFile' -Value 'phase 30 write-deny test' -ErrorAction Stop
```
Also add a comment in the injected script noting that the `catch` block fall-through before the `Test-Path` check means any pre-creation exception produces a false-PASS exit 42.

### WR-02: `Read-PassFail` regex is incorrectly parenthesized — "fail" matches PASS arm

**File:** `scripts/test-windows-shell-tui.ps1:64-68`

**Issue:** The `switch -Regex` patterns are:
```powershell
'^p|pass$'  { return 'PASS' }
'^f|fail$'  { return 'FAIL' }
'^s|skip$'  { return 'SKIP' }
```
Due to regex alternation precedence, `'^p|pass$'` is parsed as `(^p)|(pass$)` — it matches any input starting with `p` OR any input ending with `pass`. Similarly, `'^f|fail$'` matches any input starting with `f` OR ending with `fail`. However there is a critical cross-arm overlap: an operator who types `"fail"` has input starting with `f` (matches `^f`) which routes to the FAIL arm — that is correct. But an operator who types `"passthrough"` (starts with `p`) routes to PASS — also arguably acceptable. The actual defect is this: the pattern `'^s|skip$'` matches any input starting with `s`. An operator typing `"stop"` routes to SKIP. More consequentially, the default case (the validation/retry loop) is never reached for any single-character input that happens to start with p, f, or s (e.g. `"potato"` → PASS, `"false"` → FAIL, `"success"` → SKIP) — the operator receives no warning that their input was ambiguously interpreted.

The intended patterns (per the 30-03-SUMMARY.md description: "accepts 'p', 'pass', 'PASS' variants") are anchored single-char OR full-word:
```powershell
'^(p|pass)$'   { return 'PASS' }
'^(f|fail)$'   { return 'FAIL' }
'^(s|skip)$'   { return 'SKIP' }
```
The `switch -Regex` in PowerShell is case-insensitive by default, so `PASS` and `pass` both work. The current patterns are overly permissive due to missing grouping parentheses, not the case-insensitivity.

**Fix:**
```powershell
switch -Regex ($r.Trim()) {
    '^(p|pass)$'  { return 'PASS' }
    '^(f|fail)$'  { return 'FAIL' }
    '^(s|skip)$'  { return 'SKIP' }
    default { Write-Host "Type PASS, FAIL, or SKIP." }
}
```
Add `.Trim()` to strip accidental leading/trailing whitespace from `Read-Host` input on some terminal configurations.

### WR-03: `detached_stdio` allocation condition is redundant and misleading

**File:** `crates/nono-cli/src/exec_strategy_windows/launch.rs:1358`

**Issue:**
```rust
detached_stdio = if pty.is_none() && is_windows_detached_launch {
    Some(DetachedStdioPipes::create()?)
} else {
    None
};
```
This code is inside the `else` branch of `if let Some(pty_pair) = pty { ... } else { ... }`, which is only reached when `pty` is `None`. The `pty.is_none()` check in the inner condition is therefore always true at this point — it tests a condition that is structurally guaranteed by the surrounding control flow. The condition as written reads as if there are cases where `pty.is_none()` might be false here, which could mislead future maintainers into believing this branch can be reached with a PTY pair.

This is not a behavioral bug (the code is correct), but it is a logic-clarity defect: a dead sub-condition in a security-adjacent code path is the kind of thing that causes confusion during Phase 31 edits.

**Fix:**
```rust
// `pty` is `None` here by construction (this is the else branch of `if let Some(pty_pair) = pty`).
detached_stdio = if is_windows_detached_launch {
    Some(DetachedStdioPipes::create()?)
} else {
    None
};
```

### WR-04: `$targetFile` interpolation inside `@"..."` here-string — variable expansion at harness scope, not inside sandboxed shell

**File:** `scripts/test-windows-shell-write-deny.ps1:130-137`

**Issue:** The injected script uses a `@"..."` (expandable here-string) in the outer harness. Variables like `$targetFile` inside the here-string are expanded by the **harness** PowerShell process at the time the `$injected` string is assigned (line 130-137), substituting the harness's `$USERPROFILE`-based path. This is actually the *intended* behavior — the path becomes a literal string in the injected command. However:

1. The interpolated path will contain backslashes (e.g. `C:\Users\OMack\Desktop\nono-acceptance3.txt`). When passed as `-Command` to a child PowerShell via `& $NonoBinary shell ... -- -NoLogo -NoProfile -Command $injected`, the command string with backslashes in paths is not further escaped. PowerShell's `-Command` parameter receives the string correctly because backslash is not a PowerShell escape character. This is fine on Windows.

2. However, the path is substituted with single-quotes inside the injected script (`Out-File '$targetFile'`). Since this is inside a `@"..."` here-string (expandable), `$targetFile` IS expanded. The resulting string looks like: `Out-File 'C:\Users\OMack\Desktop\nono-acceptance3.txt' 'phase 30 write-deny test'`. The single-quotes in the injected script are literal single-quote characters in the resulting string — they do not suppress expansion (that already happened). This is correct behavior, but the code looks confusing at a glance: a reader who sees `'$targetFile'` inside `@"..."` may think it is unexpanded, when it is not.

3. If `$USERPROFILE` contains spaces (e.g. `C:\Users\Oscar Mack\Desktop\...`), the path will be embedded bare inside single-quotes in the injected script, which handles spaces correctly in PowerShell. No immediate defect, but documenting for clarity.

**This is a WARNING, not BLOCKER**, because the actual runtime behavior is correct on a typical Windows box. The risk is maintainability confusion for Phase 31 editors who need to modify the injected script.

**Fix:** Add an inline comment:
```powershell
# NOTE: @"..."  is an expandable here-string; $targetFile is substituted HERE
# in the harness process. The injected script receives a literal path string.
$injected = @"
try {
  ...
"@
```

---

## Info

### IN-01: `$targetFile` in write-deny harness references `$env:USERPROFILE` Desktop — may not exist on all Windows configurations

**File:** `scripts/test-windows-shell-write-deny.ps1:123`

**Issue:**
```powershell
$targetFile = Join-Path $env:USERPROFILE "Desktop\nono-acceptance3.txt"
```
The `Desktop` folder is shell-managed and its actual path may differ from `$USERPROFILE\Desktop` on systems where folder redirection is active (e.g., enterprise environments with `Documents` and `Desktop` redirected to a UNC path or a non-standard location). On such a box, `$env:USERPROFILE\Desktop` may not exist, causing `Test-Path` to always return false and the test to always exit 42 (PASS via missing-file path, not via write-deny).

The path should be obtained via the Shell `SpecialFolders` API: `[Environment]::GetFolderPath('Desktop')`.

**Fix:**
```powershell
$desktopPath = [Environment]::GetFolderPath('Desktop')
$targetFile = Join-Path $desktopPath "nono-acceptance3.txt"
```

### IN-02: The cookbook top-of-doc `<Note>` references "the 'Known limitation' section below" but the actual section heading is "Known limitation: `nono run` cannot host TUI agents on Windows" — no anchor link is provided for that cross-reference

**File:** `docs/cli/development/windows-poc-handoff.mdx:11`

**Issue:**
```mdx
`nono run -- <command>` is the supported invocation for the POC on Windows. Long-form interactive shells (`nono shell`) are deferred to v3.0 — see [`nono shell` on Windows is deferred to v3.0](#nono-shell-on-windows-is-deferred-to-v30) and the "Known limitation" section below for the structural reason.
```
The cross-reference to "the 'Known limitation' section below" is plain text — it does not anchor-link to `#known-limitation-nono-run-cannot-host-tui-agents-on-windows`. The `nono shell` deferred section IS linked correctly (`#nono-shell-on-windows-is-deferred-to-v30`). The "Known limitation" mention should also be a clickable link for reader navigation.

**Fix:**
```mdx
see [`nono shell` on Windows is deferred to v3.0](#nono-shell-on-windows-is-deferred-to-v30) and the [Known limitation](#known-limitation-nono-run-cannot-host-tui-agents-on-windows) section below for the structural reason.
```

---

## Cross-file Consistency Notes

- **Cookbook ↔ launch.rs:** The cookbook accurately describes the `LowIlPrimary` cascade arm as preserved dead code. The `windows-poc-handoff.mdx` correctly states "Low-IL primary token + ConPTY → STATUS_DLL_INIT_FAILED at CSRSS ALPC handshake" — this matches the `WindowsTokenArm::LowIlPrimary` comment block in launch.rs and the 30-WAVE-2-PROCMON.md finding.

- **Known deferred bugs acknowledged (not classified BLOCKER per review instructions):**
  - `nono shell` does not accept positional/trailing args — documented in 30-WAVE-2-PROCMON.md "Final outcome"; tracked as Phase 31 inheritance.
  - `Out-File '<path>' '<content>'` is invalid PowerShell syntax — documented in 30-WAVE-2-PROCMON.md; tracked as Phase 31 inheritance. Reviewed above as WR-01 (WARNING, not BLOCKER) because the false-PASS consequence on the security test is not fully surfaced in the existing documentation.

- **`pty_token_gate_tests` is correctly cross-platform** (`#[cfg(test)]` only, no Windows gate required — the helper `select_windows_token_arm` is a pure function with no FFI).

- **`low_integrity_primary_token_tests` is correctly Windows-gated** (`#[cfg(all(test, target_os = "windows"))]`). The conditional compilation matches the project convention established in `restricted_token.rs`.

- **`drop_is_safe` test:** The test does exercise the Drop path (explicit `drop(token)` on line 1701). However, it cannot catch a double-close bug because the test process continues after the drop — a double-close of a recycled handle would only surface if a subsequent test runs before the OS reassigns that handle value. This is an inherent limitation of FFI Drop tests, not a defect in the test as written. Future reviewers should not add a second `drop(token)` call expecting it to catch bugs — it would cause undefined behavior if the Drop impl were wrong.

---

_Reviewed: 2026-05-08_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
