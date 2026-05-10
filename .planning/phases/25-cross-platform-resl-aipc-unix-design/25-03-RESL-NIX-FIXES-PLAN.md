---
phase: 25-cross-platform-resl-aipc-unix-design
plan: 03
type: execute
wave: 1
depends_on: []
files_modified:
  - crates/nono-cli/src/exec_strategy.rs
autonomous: true
gap_closure: true
addresses: [CR-01, CR-02]
requirements: [REQ-RESL-NIX-01, REQ-RESL-NIX-02, REQ-RESL-NIX-03]

must_haves:
  truths:
    - "No format!() / println!() / eprintln!() / String calls inside the post-fork child branch of execute_supervised between fork() and exec()"
    - "--timeout set in Direct strategy mode emits a warn!() log line naming the limitation and suggesting --strategy supervised"
  artifacts:
    - path: "crates/nono-cli/src/exec_strategy.rs"
      provides: "async-signal-safe child branch error paths; Direct mode timeout warning"
      contains: "const MSG_"
  key_links:
    - from: "execute_supervised child branch"
      to: "libc::STDERR_FILENO"
      via: "libc::write with const &[u8] (no format!)"
      pattern: "const MSG_.*: &\\[u8\\] = b\""
    - from: "execute_direct"
      to: "warn! log"
      via: "resource_limits.timeout.is_some() guard"
      pattern: "timeout.*not enforced.*Direct"
---

<objective>
Fix two code-review blockers both located in `crates/nono-cli/src/exec_strategy.rs`:

- **CR-01**: Replace every `format!()` call in the post-fork child branch of `execute_supervised` with pre-allocated static `const MSG: &[u8]` byte strings. `format!()` allocates heap memory via the Rust allocator; in a multi-threaded post-fork child, if the parent held the allocator mutex at `fork()` time, the child inherits a locked mutex and the `format!()` call deadlocks. This is a correctness issue in the supervised execution path.

- **CR-02**: Add a user-visible `warn!()` log (emitted to stderr via `eprintln!` on non-verbose runs) when `--timeout` is set and the execution strategy resolves to `Direct`. The Direct strategy has no supervisor watchdog; `--timeout` is silently not enforced. Users get no feedback that their deadline will be ignored.

Purpose: Eliminate async-signal-unsafe heap allocation in the critical child post-fork window; ensure `--timeout` in Direct mode fails loudly.

Output: Modified `exec_strategy.rs` with zero `format!()`/`String` calls in the child branch and an explicit warning for Direct+timeout.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md
@.planning/phases/25-cross-platform-resl-aipc-unix-design/25-01-RESL-NIX-SUMMARY.md

<interfaces>
<!-- Key patterns from exec_strategy.rs that executor needs. -->
<!-- Already-correct async-signal-safe pattern (at line 1125, chdir error handler): -->
```rust
const MSG: &[u8] = b"nono: failed to enter child working directory\n";
// SAFETY: `write` and `_exit` are async-signal-safe and we're in
// the post-fork child path where higher-level Rust APIs are unsafe.
unsafe {
    libc::write(
        libc::STDERR_FILENO,
        MSG.as_ptr().cast::<libc::c_void>(),
        MSG.len(),
    );
    libc::_exit(126);
}
```
<!-- Use this EXACT pattern for all CR-01 replacements. -->
<!-- The STDERR_FILENO constant is libc::STDERR_FILENO (already imported). -->

<!-- CR-02 warning pattern to add in execute_direct, after resource_session_id is in scope: -->
```rust
#[cfg(any(target_os = "linux", target_os = "macos"))]
if resource_limits.timeout.is_some() {
    warn!(
        "--timeout is not enforced in Direct strategy mode; \
         use --strategy supervised for wall-clock deadline enforcement"
    );
    eprintln!(
        "nono: warning: --timeout is not enforced in Direct strategy mode; \
         use --strategy supervised"
    );
}
```
</interfaces>
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1: Replace format!() in post-fork child branch with const &[u8] static messages (CR-01)</name>
  <files>crates/nono-cli/src/exec_strategy.rs</files>
  <read_first>
    - crates/nono-cli/src/exec_strategy.rs (full child branch from fork to exec: lines 840–1145)
    - 25-REVIEW.md CR-01 section for the full list of affected line numbers: 862-863, 899, 933, 951, 994, 1011, 1054, 1071, 1093
  </read_first>
  <behavior>
    - After fix: `grep -n "format!" crates/nono-cli/src/exec_strategy.rs` in the child branch region (lines 840–1145) returns zero matches
    - After fix: every child-branch error path uses `const MSG_X: &[u8] = b"...\n";` followed by `libc::write(libc::STDERR_FILENO, MSG_X.as_ptr().cast(), MSG_X.len());`
    - Each const has a unique name (MSG_CGROUP, MSG_SOCK, MSG_SANDBOX_LINUX, MSG_SANDBOX_OTHER, MSG_SECCOMP_SEND, MSG_SECCOMP_FAIL, MSG_PROXY_SEND, MSG_PROXY_FAIL, MSG_DUMPABLE) to avoid shadowing
    - The SAFETY comment above each unsafe block is preserved (or added if missing)
  </behavior>
  <action>
    Find and replace every `format!()` call in the child branch of `execute_supervised` (between `Ok(ForkResult::Child)` and the final `unsafe { libc::_exit(127) }`). Apply the following substitutions:

    **Site 1 — line ~862 (cgroup placement failure):**
    Replace:
    ```rust
    let detail = format!("nono: failed to place child in cgroup: {}\n", e);
    let msg = detail.as_bytes();
    unsafe {
        libc::write(libc::STDERR_FILENO, msg.as_ptr().cast::<libc::c_void>(), msg.len());
        libc::_exit(126);
    }
    ```
    With:
    ```rust
    const MSG_CGROUP: &[u8] = b"nono: failed to place child in cgroup\n";
    // SAFETY: write and _exit are async-signal-safe; we are in the post-fork
    // child branch where heap allocation is unsafe.
    unsafe {
        libc::write(libc::STDERR_FILENO, MSG_CGROUP.as_ptr().cast::<libc::c_void>(), MSG_CGROUP.len());
        libc::_exit(126);
    }
    ```

    **Site 2 — line ~899 (clear_close_on_exec failure on supervisor socket):**
    Replace:
    ```rust
    let detail = format!(
        "nono: failed to clear close-on-exec on supervisor socket: {}\n",
        e
    );
    let msg = detail.as_bytes();
    unsafe {
        libc::write(libc::STDERR_FILENO, msg.as_ptr().cast::<libc::c_void>(), msg.len());
        libc::_exit(126);
    }
    ```
    With:
    ```rust
    const MSG_SOCK: &[u8] = b"nono: failed to clear close-on-exec on supervisor socket\n";
    // SAFETY: write and _exit are async-signal-safe.
    unsafe {
        libc::write(libc::STDERR_FILENO, MSG_SOCK.as_ptr().cast::<libc::c_void>(), MSG_SOCK.len());
        libc::_exit(126);
    }
    ```

    **Site 3 — line ~933 (Sandbox::apply() failure, Linux #[cfg] branch):**
    Replace:
    ```rust
    let detail = format!("nono: failed to apply sandbox in supervised child: {}\n", e);
    let msg = detail.as_bytes();
    unsafe {
        libc::write(libc::STDERR_FILENO, msg.as_ptr().cast::<libc::c_void>(), msg.len());
        libc::_exit(126);
    }
    ```
    With:
    ```rust
    const MSG_SANDBOX_LINUX: &[u8] = b"nono: failed to apply sandbox in supervised child\n";
    // SAFETY: write and _exit are async-signal-safe.
    unsafe {
        libc::write(libc::STDERR_FILENO, MSG_SANDBOX_LINUX.as_ptr().cast::<libc::c_void>(), MSG_SANDBOX_LINUX.len());
        libc::_exit(126);
    }
    ```

    **Site 4 — line ~951 (Sandbox::apply() failure, non-Linux #[cfg(not)] branch):**
    Replace:
    ```rust
    let detail = format!("nono: failed to apply sandbox in supervised child: {}\n", e);
    let msg = detail.as_bytes();
    unsafe {
        libc::write(libc::STDERR_FILENO, msg.as_ptr().cast::<libc::c_void>(), msg.len());
        libc::_exit(126);
    }
    ```
    With:
    ```rust
    const MSG_SANDBOX_OTHER: &[u8] = b"nono: failed to apply sandbox in supervised child\n";
    // SAFETY: write and _exit are async-signal-safe.
    unsafe {
        libc::write(libc::STDERR_FILENO, MSG_SANDBOX_OTHER.as_ptr().cast::<libc::c_void>(), MSG_SANDBOX_OTHER.len());
        libc::_exit(126);
    }
    ```

    **Site 5 — line ~994 (failed to send seccomp notify fd):**
    Replace:
    ```rust
    let detail = format!(
        "nono: failed to send seccomp notify fd to supervisor: {}\n",
        e
    );
    let msg = detail.as_bytes();
    unsafe {
        libc::write(libc::STDERR_FILENO, msg.as_ptr().cast::<libc::c_void>(), msg.len());
        libc::_exit(126);
    }
    ```
    With:
    ```rust
    const MSG_SECCOMP_SEND: &[u8] = b"nono: failed to send seccomp notify fd to supervisor\n";
    // SAFETY: write and _exit are async-signal-safe.
    unsafe {
        libc::write(libc::STDERR_FILENO, MSG_SECCOMP_SEND.as_ptr().cast::<libc::c_void>(), MSG_SECCOMP_SEND.len());
        libc::_exit(126);
    }
    ```

    **Site 6 — line ~1011 (seccomp-notify not available — non-fatal, no _exit):**
    Replace:
    ```rust
    let detail = format!(
        "nono: seccomp-notify not available, expansion disabled: {}\n",
        e
    );
    let msg = detail.as_bytes();
    unsafe {
        libc::write(libc::STDERR_FILENO, msg.as_ptr().cast::<libc::c_void>(), msg.len());
    }
    ```
    With:
    ```rust
    const MSG_SECCOMP_FAIL: &[u8] = b"nono: seccomp-notify not available, expansion disabled\n";
    // SAFETY: write is async-signal-safe; this is a non-fatal warning (no _exit).
    unsafe {
        libc::write(libc::STDERR_FILENO, MSG_SECCOMP_FAIL.as_ptr().cast::<libc::c_void>(), MSG_SECCOMP_FAIL.len());
    }
    ```

    **Site 7 — line ~1054 (failed to send proxy seccomp notify fd):**
    Replace:
    ```rust
    let detail = format!(
        "nono: failed to send proxy seccomp notify fd: {}\n",
        e
    );
    let msg = detail.as_bytes();
    unsafe {
        libc::write(libc::STDERR_FILENO, msg.as_ptr().cast::<libc::c_void>(), msg.len());
        libc::_exit(126);
    }
    ```
    With:
    ```rust
    const MSG_PROXY_SEND: &[u8] = b"nono: failed to send proxy seccomp notify fd\n";
    // SAFETY: write and _exit are async-signal-safe.
    unsafe {
        libc::write(libc::STDERR_FILENO, MSG_PROXY_SEND.as_ptr().cast::<libc::c_void>(), MSG_PROXY_SEND.len());
        libc::_exit(126);
    }
    ```

    **Site 8 — line ~1071 (seccomp proxy filter not available):**
    Replace:
    ```rust
    let detail = format!("nono: seccomp proxy filter not available: {}\n", e);
    let msg = detail.as_bytes();
    unsafe {
        libc::write(libc::STDERR_FILENO, msg.as_ptr().cast::<libc::c_void>(), msg.len());
        libc::_exit(126);
    }
    ```
    With:
    ```rust
    const MSG_PROXY_FAIL: &[u8] = b"nono: seccomp proxy filter not available\n";
    // SAFETY: write and _exit are async-signal-safe.
    unsafe {
        libc::write(libc::STDERR_FILENO, MSG_PROXY_FAIL.as_ptr().cast::<libc::c_void>(), MSG_PROXY_FAIL.len());
        libc::_exit(126);
    }
    ```

    **Site 9 — line ~1093 (PR_SET_DUMPABLE(0) failure):**
    Replace:
    ```rust
    let detail = format!(
        "nono: failed to set PR_SET_DUMPABLE(0) in supervised child: {}\n",
        e
    );
    let msg = detail.as_bytes();
    unsafe {
        libc::write(libc::STDERR_FILENO, msg.as_ptr().cast::<libc::c_void>(), msg.len());
        ...
    }
    ```
    With:
    ```rust
    const MSG_DUMPABLE: &[u8] = b"nono: failed to set PR_SET_DUMPABLE(0) in supervised child\n";
    // SAFETY: write and _exit are async-signal-safe.
    unsafe {
        libc::write(libc::STDERR_FILENO, MSG_DUMPABLE.as_ptr().cast::<libc::c_void>(), MSG_DUMPABLE.len());
        ...
    }
    ```

    **Const placement rule:** Each `const MSG_X` must be declared immediately before the `unsafe` block that uses it, inside the same scope. Do NOT declare all consts at the top of the child arm — scoped declarations are cleaner and prevent accidental reuse.

    **Do NOT change:** The `b"nono: ..."` strings on lines outside the child branch (parent side, in `Ok(ForkResult::Parent { ... })`). Do NOT change the already-correct chdir handler at line ~1125 (it is already async-signal-safe).
  </action>
  <verify>
    <automated>
      grep -n "format!" crates/nono-cli/src/exec_strategy.rs | grep -v "//.*format" | grep -v "nono-cli/src/exec_strategy.rs:[0-9]*:.*ForkResult::Parent" | head -20
      cargo build --package nono-cli 2>&1 | tail -20
      cargo clippy --package nono-cli -- -D warnings -D clippy::unwrap_used 2>&1 | tail -20
    </automated>
  </verify>
  <acceptance_criteria>
    1. `grep -c "format!" crates/nono-cli/src/exec_strategy.rs` is reduced by exactly 9 (the 9 child-branch sites replaced). Any remaining `format!` calls are in the parent branch or helper functions outside the fork region.
    2. `grep -n "const MSG_" crates/nono-cli/src/exec_strategy.rs` returns at least 9 new lines (MSG_CGROUP, MSG_SOCK, MSG_SANDBOX_LINUX, MSG_SANDBOX_OTHER, MSG_SECCOMP_SEND, MSG_SECCOMP_FAIL, MSG_PROXY_SEND, MSG_PROXY_FAIL, MSG_DUMPABLE).
    3. `cargo build --package nono-cli` exits 0 with no errors.
    4. `cargo clippy --package nono-cli -- -D warnings -D clippy::unwrap_used` exits 0.
  </acceptance_criteria>
  <done>All 9 format!() call sites in the post-fork child branch replaced with static const &[u8] byte strings. Build and clippy pass clean.</done>
</task>

<task type="auto">
  <name>Task 2: Emit warn!() + eprintln!() when --timeout is set in Direct strategy mode (CR-02)</name>
  <files>crates/nono-cli/src/exec_strategy.rs</files>
  <read_first>
    - crates/nono-cli/src/exec_strategy.rs (execute_direct function: lines 423–483)
    - 25-REVIEW.md CR-02 section for the exact warning text required
  </read_first>
  <action>
    In `execute_direct`, immediately after the function's existing `info!(...)` log call (around line 449), add the following block:

    ```rust
    // CR-02: --timeout is not enforced in Direct strategy mode (no supervisor
    // watchdog available). Warn the user explicitly rather than silently ignoring.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if resource_limits.timeout.is_some() {
        warn!(
            "--timeout is not enforced in Direct strategy mode; \
             use --strategy supervised for wall-clock deadline enforcement"
        );
        eprintln!(
            "nono: warning: --timeout is not enforced in Direct strategy mode; \
             use --strategy supervised"
        );
    }
    ```

    Place this block AFTER the `info!("Executing (direct): ...")` line and BEFORE `let mut cmd = Command::new(...)`. This ensures the warning fires before any child process is forked.

    The `eprintln!` ensures the warning reaches the user even when `RUST_LOG` is not set (matching the project's "Fail Secure" UX principle: at minimum the user must know enforcement is not active).
  </action>
  <verify>
    <automated>
      grep -n "timeout.*not enforced.*Direct\|Direct.*timeout.*not enforced" crates/nono-cli/src/exec_strategy.rs
      cargo build --package nono-cli 2>&1 | tail -10
      cargo clippy --package nono-cli -- -D warnings -D clippy::unwrap_used 2>&1 | tail -10
    </automated>
  </verify>
  <acceptance_criteria>
    1. `grep -c "timeout.*not enforced.*Direct\|use --strategy supervised" crates/nono-cli/src/exec_strategy.rs` returns at least 2 (one in warn!, one in eprintln!).
    2. The warning block is guarded with `#[cfg(any(target_os = "linux", target_os = "macos"))]` so it does not affect Windows builds (where resource_limits parameter does not exist).
    3. `cargo build --package nono-cli` exits 0.
    4. `cargo clippy --package nono-cli -- -D warnings -D clippy::unwrap_used` exits 0.
    5. `cargo fmt --check --all` exits 0.
  </acceptance_criteria>
  <done>execute_direct emits a warn!() log + eprintln!() to stderr when --timeout is set. Build, clippy, fmt all pass.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| post-fork child → kernel | Child branch runs in async-signal-unsafe context; heap allocator state inherited from parent |
| user CLI → execute_direct | User-supplied --timeout flag accepted but not enforced silently |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-25-03-01 | Denial of Service | execute_supervised post-fork child branch | mitigate | CR-01: Replace format!() with const &[u8] static strings, eliminating allocator-lock deadlock risk in child |
| T-25-03-02 | Elevation of Privilege | execute_direct --timeout silent non-enforcement | mitigate | CR-02: Emit warn!() + eprintln!() so user knows timeout is not active; recommend supervised mode |
| T-25-03-03 | Spoofing | Child-branch error messages | accept | Static messages lose error detail (e.g., errno); this is acceptable — the alternative (heap allocation) is less safe than the reduced diagnostic quality |
</threat_model>

<verification>
After both tasks:

```bash
# Confirm zero format! calls in child branch (lines 840–1145)
awk 'NR>=840 && NR<=1145' crates/nono-cli/src/exec_strategy.rs | grep -c "format!"
# Expected: 0

# Confirm const MSG_ count
grep -c "const MSG_" crates/nono-cli/src/exec_strategy.rs
# Expected: >= 9

# Confirm timeout warning present
grep -c "timeout.*not enforced" crates/nono-cli/src/exec_strategy.rs
# Expected: >= 2 (one per warn!/eprintln!)

# Full build + lint
cargo build --workspace
cargo clippy --workspace -- -D warnings -D clippy::unwrap_used
cargo fmt --check --all
```
</verification>

<success_criteria>
- `awk 'NR>=840 && NR<=1145' crates/nono-cli/src/exec_strategy.rs | grep "format!"` returns empty
- `grep -c "const MSG_" crates/nono-cli/src/exec_strategy.rs` >= 9
- `grep -c "timeout.*not enforced" crates/nono-cli/src/exec_strategy.rs` >= 2
- `cargo build --workspace` exits 0
- `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` exits 0
- `cargo fmt --check --all` exits 0
</success_criteria>

<output>
After completion, create `.planning/phases/25-cross-platform-resl-aipc-unix-design/25-03-RESL-NIX-FIXES-SUMMARY.md`
</output>
