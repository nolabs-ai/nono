---
phase: 25-cross-platform-resl-aipc-unix-design
plan: 05
type: execute
wave: 1
depends_on: []
files_modified:
  - crates/nono-cli/src/exec_strategy.rs
  - crates/nono-cli/tests/resl_nix_async_signal_safety.rs
autonomous: true
gap_closure: true
addresses: [CR-01-RESIDUAL, WR-A, WR-B]
requirements: [REQ-RESL-NIX-01, REQ-RESL-NIX-02, REQ-RESL-NIX-03]

must_haves:
  truths:
    - "clear_close_on_exec returns std::io::Result<()> using std::io::Error::last_os_error() — zero format!() calls in its body — and is therefore safe to invoke from the post-fork child branch"
    - "The post-fork child branch in execute_supervised is delimited by sentinel comments // CR-01-CHILD-ARM-START and // CR-01-CHILD-ARM-END so the regression test scopes its scan to a stable, self-documenting region rather than the first match of `Ok(ForkResult::Child) => {`"
    - "The regression test cr_01_no_format_macro_in_post_fork_child_branch scopes its source scan by sentinel comments AND additionally asserts that the body of clear_close_on_exec contains zero format!() calls — closing the call-graph gap without requiring full reachability analysis"
  artifacts:
    - path: "crates/nono-cli/src/exec_strategy.rs"
      provides: "clear_close_on_exec converted to std::io::Result<()> with std::io::Error::last_os_error(); call site at line 950 updated; sentinel comments around production child arm"
      contains: "std::io::Error::last_os_error()"
    - path: "crates/nono-cli/tests/resl_nix_async_signal_safety.rs"
      provides: "Sentinel-based scoping (replaces brace-counting + first-match find), plus an explicit assertion that clear_close_on_exec body has zero format!() calls"
      contains: "CR-01-CHILD-ARM-START"
  key_links:
    - from: "execute_supervised post-fork child branch (line 950)"
      to: "clear_close_on_exec (line 2759)"
      via: "direct call — both paths now async-signal-safe (no heap allocation on fcntl error)"
      pattern: "clear_close_on_exec\\(fd\\)"
    - from: "cr_01_no_format_macro_in_post_fork_child_branch test"
      to: "clear_close_on_exec body in exec_strategy.rs"
      via: "explicit per-function assertion that scans the helper's body for format!()"
      pattern: "fn clear_close_on_exec"
    - from: "cr_01_no_format_macro_in_post_fork_child_branch test"
      to: "Production child arm in execute_supervised"
      via: "sentinel-comment scoping (// CR-01-CHILD-ARM-START / // CR-01-CHILD-ARM-END)"
      pattern: "CR-01-CHILD-ARM-(START|END)"
---

<objective>
Close CR-01-RESIDUAL (BLOCKER) and bundle WR-A + WR-B (test-scaffolding fragility) into a single coherent change because all three are inter-locked: the same sentinel-comment scoping mechanism that addresses WR-A (first-match fragility) and WR-B (string-literal/comment-aware brace counting) also makes the strengthened CR-01-RESIDUAL test (option b: "scope by sentinel + explicit clear_close_on_exec body assertion") trivial to add.

Per 25-VERIFICATION.md `gaps.missing` block:

1. **CR-01-RESIDUAL fix** — Convert `clear_close_on_exec` (currently `fn clear_close_on_exec(fd: i32) -> Result<()>` at exec_strategy.rs:2759) to return `std::io::Result<()>` and replace both `format!(...)` error constructions with `std::io::Error::last_os_error()`. `last_os_error()` captures the errno into a stack-resident `io::Error::Repr` for raw OS errors and does not allocate. The call site at exec_strategy.rs:950 (`if let Err(_e) = clear_close_on_exec(fd)`) already discards the error variant via `_e`, so the signature change is local and does not propagate to the rest of the module.

2. **WR-A + WR-B fix** — Add sentinel comments `// CR-01-CHILD-ARM-START` (immediately after the opening `{` of `Ok(ForkResult::Child) => {` at line 844) and `// CR-01-CHILD-ARM-END` (immediately before the closing `}` at line 1196 of the arm body). Replace the `find_child_branch_lines` helper in the regression test with a sentinel-based slicer. This eliminates both (a) the "first match wins" fragility that ignores the two test-helper child arms at lines 3551 and 3647, and (b) the brace-counter that ignores string literals and block comments.

3. **CR-01-RESIDUAL test strengthening (option b from VERIFICATION.md missing block)** — In `cr_01_no_format_macro_in_post_fork_child_branch`, after the existing region scan, add a separate assertion that the body of `clear_close_on_exec` contains zero `format!(` calls. Slice the function by name (`fn clear_close_on_exec(`) up to its matching `}` and assert zero `format!(` matches inside. This closes the call-graph gap without committing to full reachability analysis (which would have to also harden Sandbox::apply, install_seccomp_notify, send_fd_via_socket, install_seccomp_proxy_filter, set_dumpable — explicitly deferred per VERIFICATION.md "do NOT re-litigate" guidance and CONTEXT.md scope-lock).

This plan does NOT re-litigate the architectural inconsistency raised in 25-REVIEW-GAPS.md about Sandbox::apply / seccomp helpers also allocating. Per the gap-closure scope, those are DEFERRED — clear_close_on_exec is the one helper called from the child error path that lies *outside* the documented "Sandbox::apply allocates by design" exception.

Purpose: Make the post-fork child branch's allocator-free contract robust along the fcntl-failure path AND make the regression-test scaffolding robust against future refactors of the surrounding match arm.

Output: Modified `crates/nono-cli/src/exec_strategy.rs` (clear_close_on_exec signature change + sentinel comments) and `crates/nono-cli/tests/resl_nix_async_signal_safety.rs` (sentinel-based scoping + explicit clear_close_on_exec body assertion).
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
@$HOME/.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md
@.planning/phases/25-cross-platform-resl-aipc-unix-design/25-CONTEXT.md
@.planning/phases/25-cross-platform-resl-aipc-unix-design/25-VERIFICATION.md
@.planning/phases/25-cross-platform-resl-aipc-unix-design/25-REVIEW-GAPS.md
@.planning/phases/25-cross-platform-resl-aipc-unix-design/25-03-RESL-NIX-FIXES-SUMMARY.md

<interfaces>
<!-- The defective helper, exec_strategy.rs lines 2758-2782 (read verbatim from source as of branch tip): -->
```rust
/// Clear `FD_CLOEXEC` on a file descriptor so it survives `execve()`.
fn clear_close_on_exec(fd: i32) -> Result<()> {
    // SAFETY: `fcntl` is called with a valid fd owned by this process.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(NonoError::SandboxInit(format!(
            "fcntl(F_GETFD) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let new_flags = flags & !libc::FD_CLOEXEC;
    if new_flags != flags {
        // SAFETY: `fcntl` is called with a valid fd and descriptor flags.
        let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, new_flags) };
        if rc < 0 {
            return Err(NonoError::SandboxInit(format!(
                "fcntl(F_SETFD) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    Ok(())
}
```

<!-- The call site in the post-fork child branch, exec_strategy.rs lines 945-963 (verbatim): -->
```rust
            // The supervisor socket must survive exec into the sandboxed command,
            // and later into any helper (`open-url-helper`) that needs to speak
            // IPC back to the unsandboxed parent. `UnixStream::pair()` creates
            // fds with close-on-exec set, so clear it on the child end here.
            if let Some(fd) = child_sock_fd {
                if let Err(_e) = clear_close_on_exec(fd) {
                    // CR-01: static byte string in post-fork child.
                    const MSG_SOCK: &[u8] =
                        b"nono: failed to clear close-on-exec on supervisor socket\n";
                    // SAFETY: write and _exit are async-signal-safe.
                    unsafe {
                        libc::write(
                            libc::STDERR_FILENO,
                            MSG_SOCK.as_ptr().cast::<libc::c_void>(),
                            MSG_SOCK.len(),
                        );
                        libc::_exit(126);
                    }
                }
            }
```

<!-- The unit test at exec_strategy.rs lines 3889-3906 that exercises clear_close_on_exec: -->
```rust
#[test]
fn test_clear_close_on_exec_clears_flag() {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    let (a, _b) = UnixStream::pair().expect("socketpair");
    let fd = a.as_raw_fd();

    let before = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(before >= 0, "F_GETFD before failed");
    assert_ne!(before & libc::FD_CLOEXEC, 0, "fd should start CLOEXEC");

    clear_close_on_exec(fd).expect("clear cloexec");
    // ↑ `.expect()` works with both `nono::Result<()>` and `std::io::Result<()>` —
    //   no test change needed.

    let after = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(after >= 0, "F_GETFD after failed");
    assert_eq!(after & libc::FD_CLOEXEC, 0, "fd should not be CLOEXEC");
}
```

<!-- The brace-counting helper to be replaced, tests/resl_nix_async_signal_safety.rs lines 47-79: -->
```rust
fn find_child_branch_lines(src: &str) -> (usize, usize) {
    let marker = "Ok(ForkResult::Child) => {";
    let start_byte = src
        .find(marker)
        .expect("expected `Ok(ForkResult::Child) => {` marker in exec_strategy.rs");

    // Count braces from the opening `{` of the arm body.
    let body_start = start_byte + marker.len() - 1;
    let bytes = src.as_bytes();
    let mut depth = 0i32;
    let mut end_byte = body_start;
    for (i, b) in bytes.iter().enumerate().skip(body_start) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    end_byte = i;
                    break;
                }
            }
            _ => {}
        }
    }
    // ... line conversion ...
}
```

<!-- All three Ok(ForkResult::Child) sites confirmed via grep:
   exec_strategy.rs:844   (production — child arm to be sentinel-scoped)
   exec_strategy.rs:3551  (test helper — must NOT be scoped by the regression test)
   exec_strategy.rs:3647  (test helper — must NOT be scoped by the regression test)
-->

<!-- The closing `}` of the production child arm is at exec_strategy.rs line 1196.
     The next line (1197) is `Ok(ForkResult::Parent { child }) => {`.
     This is the verified end-line for the sentinel placement. -->

<!-- NonoError variant in use (no signature change cascades because the call site discards _e):
   NonoError::SandboxInit(String) — currently used inside clear_close_on_exec; will be removed.
   std::io::Error — replacement type (raw OS error variant is stack-resident, no heap alloc).
-->
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Add sentinel comments around the production post-fork child arm</name>
  <files>crates/nono-cli/src/exec_strategy.rs</files>
  <read_first>
    - crates/nono-cli/src/exec_strategy.rs lines 840-848 (the `Ok(ForkResult::Child) => {` opener at 844 and surrounding context)
    - crates/nono-cli/src/exec_strategy.rs lines 1190-1200 (the closing `}` of the child arm body at 1196 and the `Ok(ForkResult::Parent { child }) => {` opener at 1197)
    - 25-CONTEXT.md § "D-19 cross-phase byte-identical preservation" — these edits are inside `#[cfg(unix)]` execute_supervised, NOT touching exec_strategy_windows or sandbox/windows.rs
  </read_first>
  <action>
    Add exactly two sentinel comments inside the body of the production `Ok(ForkResult::Child) => {` arm at exec_strategy.rs:844.

    **Sentinel 1 — START** (after the opening `{`):

    Locate line 844 which currently reads:
    ```
            Ok(ForkResult::Child) => {
    ```
    Insert a NEW line immediately after line 844 (so the START sentinel becomes line 845, and all subsequent lines shift down by 1):
    ```
                // CR-01-CHILD-ARM-START — DO NOT REMOVE.
                // The regression test cr_01_no_format_macro_in_post_fork_child_branch
                // scopes its scan from this sentinel to CR-01-CHILD-ARM-END below.
                // Adding `format!()`, `println!()`, `eprintln!()`, or any heap-allocating
                // call between these two sentinels is forbidden — the post-fork child
                // runs in async-signal-unsafe context and may inherit a locked allocator
                // mutex from the parent. See tests/resl_nix_async_signal_safety.rs.
    ```

    **Sentinel 2 — END** (immediately before the closing `}` of the child arm):

    Locate line 1196 which currently reads:
    ```
                unsafe { libc::_exit(127) }
            }
    ```
    Specifically: line 1195 is `unsafe { libc::_exit(127) }` and line 1196 is the bare `}` that closes the child arm. Insert a NEW line immediately before line 1196 (the closing `}`):
    ```
                // CR-01-CHILD-ARM-END — DO NOT REMOVE. See sentinel above for rationale.
    ```

    The resulting region should look like:
    ```
            Ok(ForkResult::Child) => {
                // CR-01-CHILD-ARM-START — DO NOT REMOVE.
                // ...
                ... existing child arm body unchanged ...
                unsafe { libc::_exit(127) }
                // CR-01-CHILD-ARM-END — DO NOT REMOVE. See sentinel above for rationale.
            }
    ```

    **Critical invariants:**
    - Do NOT modify any code inside the existing child arm body — only add the two comment lines at the boundaries.
    - Do NOT add sentinels around the test-helper child arms at lines 3551 and 3647. Those are intentionally out of scope for the regression test.
    - The text `CR-01-CHILD-ARM-START` and `CR-01-CHILD-ARM-END` MUST appear EXACTLY as written (case-sensitive, dash-separated) — Task 3's regression test searches for these literal strings.
    - These are line comments (`//`), not doc comments (`///`) — the test in Task 3 strips line comments before scanning, so sentinels are stripped during scanning but their START/END positions are recorded BEFORE stripping.

    No other changes to exec_strategy.rs in this task.
  </action>
  <verify>
    <automated>
      grep -c "CR-01-CHILD-ARM-START" crates/nono-cli/src/exec_strategy.rs
      grep -c "CR-01-CHILD-ARM-END" crates/nono-cli/src/exec_strategy.rs
      grep -n "CR-01-CHILD-ARM-START\|CR-01-CHILD-ARM-END" crates/nono-cli/src/exec_strategy.rs
      cargo build --package nono-cli 2>&1 | tail -10
      cargo fmt --check --all 2>&1 | tail -10
    </automated>
  </verify>
  <acceptance_criteria>
    1. `grep -c "CR-01-CHILD-ARM-START" crates/nono-cli/src/exec_strategy.rs` returns exactly 1.
    2. `grep -c "CR-01-CHILD-ARM-END" crates/nono-cli/src/exec_strategy.rs` returns exactly 1.
    3. The line number of `CR-01-CHILD-ARM-START` is greater than the line number of the production `Ok(ForkResult::Child) => {` (currently 844, may shift slightly after sentinel insertion).
    4. The line number of `CR-01-CHILD-ARM-END` is greater than `CR-01-CHILD-ARM-START` and less than the line number containing `Ok(ForkResult::Parent { child }) => {`.
    5. `cargo build --package nono-cli` exits 0 (sentinels are valid Rust line comments).
    6. `cargo fmt --check --all` exits 0 (line comments do not affect formatting).
    7. The grep -n output shows ONLY two lines — no sentinels accidentally added around the test-helper child arms at 3551/3647.
  </acceptance_criteria>
  <done>Two sentinel line-comments added inside the production child arm body — one immediately after the opening `{` and one immediately before the closing `}`. Build clean, fmt clean. No sentinels around test-helper child arms.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Convert clear_close_on_exec to std::io::Result with stack-resident error</name>
  <files>crates/nono-cli/src/exec_strategy.rs</files>
  <read_first>
    - crates/nono-cli/src/exec_strategy.rs lines 2758-2782 (clear_close_on_exec definition — verbatim above in &lt;interfaces&gt;)
    - crates/nono-cli/src/exec_strategy.rs lines 945-963 (call site in post-fork child arm — verbatim above)
    - crates/nono-cli/src/exec_strategy.rs lines 3889-3906 (existing unit test test_clear_close_on_exec_clears_flag — `.expect("clear cloexec")` works on both Result types unchanged)
    - 25-VERIFICATION.md `gaps.missing` block (canonical fix recipe)
    - 25-REVIEW-GAPS.md CR-01-RESIDUAL § "Fix" subsection (the 6-line code excerpt that the planner is copying verbatim)
  </read_first>
  <behavior>
    - After fix: `clear_close_on_exec(fd)` returns `std::io::Result<()>`. On `fcntl(F_GETFD)` failure, returns `Err(std::io::Error::last_os_error())` — no `format!()` call, no `String` allocation. On `fcntl(F_SETFD)` failure, same.
    - After fix: the existing unit test `test_clear_close_on_exec_clears_flag` at exec_strategy.rs:3890 passes unchanged (the `.expect("clear cloexec")` line works for any `Result` type).
    - After fix: the call site at exec_strategy.rs:950 (`if let Err(_e) = clear_close_on_exec(fd)`) compiles unchanged because the `_e` discard pattern accepts any error variant; the `MSG_SOCK` static byte string + `_exit(126)` path is preserved verbatim.
    - After fix: `grep "format!" exec_strategy.rs:2758..2785` returns ZERO matches.
    - After fix: `cargo clippy --package nono-cli -- -D warnings -D clippy::unwrap_used` exits 0 — the new code uses no `.unwrap()` / `.expect()` in production.
  </behavior>
  <action>
    Replace the entire body of `clear_close_on_exec` at exec_strategy.rs:2758-2782 with the verbatim code below.

    **Source location:** Lines 2758 (the `///` doc comment opener) through 2782 (the closing `}` of the function).

    **Replacement (paste verbatim):**

    ```rust
    /// Clear `FD_CLOEXEC` on a file descriptor so it survives `execve()`.
    ///
    /// Returns `std::io::Result<()>` so callers in async-signal-unsafe contexts
    /// (post-fork child) can react to failure without triggering heap allocation.
    /// `std::io::Error::last_os_error()` captures the errno into a stack-resident
    /// `io::Error::Repr` for raw OS errors and does NOT allocate — this is the
    /// CR-01-RESIDUAL fix per 25-VERIFICATION.md gaps.missing block.
    fn clear_close_on_exec(fd: i32) -> std::io::Result<()> {
        // SAFETY: `fcntl` is called with a valid fd owned by this process.
        // `fcntl` itself is async-signal-safe (POSIX).
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let new_flags = flags & !libc::FD_CLOEXEC;
        if new_flags != flags {
            // SAFETY: `fcntl` is called with a valid fd and descriptor flags.
            let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, new_flags) };
            if rc < 0 {
                return Err(std::io::Error::last_os_error());
            }
        }

        Ok(())
    }
    ```

    **DO NOT** modify any other code in exec_strategy.rs in this task — the call site at line 950 (which currently reads `if let Err(_e) = clear_close_on_exec(fd) {`) compiles against the new signature unchanged because the `_e` pattern matches any error type. The unit test at line 3890 (`clear_close_on_exec(fd).expect("clear cloexec")`) also compiles unchanged because `.expect(&str)` is defined on every `Result<T, E>` where `E: Debug`, and `std::io::Error: Debug`.

    **Verify the call site is untouched** by running:
    ```bash
    grep -n "if let Err(_e) = clear_close_on_exec" crates/nono-cli/src/exec_strategy.rs
    ```
    Expected: exactly one match in the post-fork child arm (line ~950, may shift by 8 lines due to Task 1's sentinels).

    **Why std::io::Error::last_os_error() does not allocate:**
    `std::io::Error` has a `Repr` enum with three variants: `Os(i32)`, `Simple(ErrorKind)`, and `Custom(Box<...>)`. Only `Custom` allocates. `Error::last_os_error()` constructs the `Os` variant by reading `errno` directly — the entire `io::Error` is stack-resident. This is documented in std::io::Error's source and is the canonical recipe for capturing errno in async-signal-safe contexts.

    No other changes to exec_strategy.rs in this task.
  </action>
  <verify>
    <automated>
      grep -n "fn clear_close_on_exec" crates/nono-cli/src/exec_strategy.rs
      grep -c "format!" crates/nono-cli/src/exec_strategy.rs | head -1
      awk '/^fn clear_close_on_exec/,/^\}/' crates/nono-cli/src/exec_strategy.rs | grep -c "format!"
      awk '/^fn clear_close_on_exec/,/^\}/' crates/nono-cli/src/exec_strategy.rs | grep -c "last_os_error"
      awk '/^fn clear_close_on_exec/,/^\}/' crates/nono-cli/src/exec_strategy.rs | grep -c "NonoError::SandboxInit"
      awk '/^fn clear_close_on_exec/,/^\}/' crates/nono-cli/src/exec_strategy.rs | grep -c "std::io::Result"
      grep -n "if let Err(_e) = clear_close_on_exec" crates/nono-cli/src/exec_strategy.rs
      cargo build --package nono-cli 2>&1 | tail -10
      cargo test --package nono-cli test_clear_close_on_exec_clears_flag 2>&1 | tail -10
      cargo clippy --package nono-cli -- -D warnings -D clippy::unwrap_used 2>&1 | tail -10
    </automated>
  </verify>
  <acceptance_criteria>
    1. `grep -n "fn clear_close_on_exec" crates/nono-cli/src/exec_strategy.rs` returns exactly 2 matches: the function definition and the unit test (`fn test_clear_close_on_exec_clears_flag`).
    2. The function signature line for `clear_close_on_exec` MUST contain the substring `-> std::io::Result<()>` (verifiable: `grep "fn clear_close_on_exec(fd: i32) -> std::io::Result<()>" exec_strategy.rs` returns 1).
    3. Inside the body of `clear_close_on_exec` (using `awk '/^fn clear_close_on_exec/,/^\}/'`), `grep -c "format!"` returns 0.
    4. Inside the body of `clear_close_on_exec`, `grep -c "last_os_error"` returns 2 (one per fcntl error path).
    5. Inside the body of `clear_close_on_exec`, `grep -c "NonoError::SandboxInit"` returns 0 (the old error variant is gone from this function).
    6. `grep -n "if let Err(_e) = clear_close_on_exec" exec_strategy.rs` returns exactly 1 match (the call site in the post-fork child arm — proves the call site was not accidentally edited).
    7. `cargo build --package nono-cli` exits 0.
    8. `cargo test --package nono-cli test_clear_close_on_exec_clears_flag` exits 0 (the existing test passes against the new signature unchanged).
    9. `cargo clippy --package nono-cli -- -D warnings -D clippy::unwrap_used` exits 0.
  </acceptance_criteria>
  <done>clear_close_on_exec returns std::io::Result&lt;()&gt; using std::io::Error::last_os_error() on both fcntl error paths. Zero format!() calls in its body. Zero NonoError::SandboxInit constructions in its body. Call site at line 950 unchanged. Existing unit test passes. Clippy clean.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 3: Strengthen regression test — sentinel scoping + clear_close_on_exec body assertion</name>
  <files>crates/nono-cli/tests/resl_nix_async_signal_safety.rs</files>
  <read_first>
    - crates/nono-cli/tests/resl_nix_async_signal_safety.rs (entire file — 242 lines)
    - 25-VERIFICATION.md `gaps.missing` block bullet 2 (canonical strengthening recipe — option b: sentinel + per-helper assertion)
    - 25-REVIEW-GAPS.md WR-A and WR-B sections (the rationale for sentinel-based scoping)
  </read_first>
  <behavior>
    - After fix: `find_child_branch_lines` is replaced by a sentinel-comment-based slicer that locates `// CR-01-CHILD-ARM-START` and `// CR-01-CHILD-ARM-END` and returns the inclusive line range between them. No brace counting; no first-match-wins fragility.
    - After fix: A new helper `slice_function_body(src: &str, fn_signature: &str) -> String` exists and is used to extract the body of a named function by signature. Used for the per-helper clear_close_on_exec assertion. (This helper uses brace counting, but only on a small region anchored by an exact signature string match — which is the lowest-risk shape because the signature `fn clear_close_on_exec(fd: i32) -> std::io::Result<()> {` is unique and stable.)
    - After fix: The existing test `cr_01_no_format_macro_in_post_fork_child_branch` keeps its existing region scan (now sentinel-scoped) AND adds an additional assertion: the body of `clear_close_on_exec` contains zero `format!(` matches.
    - After fix: All other tests in the file (`cr_01_and_wr_02_const_msg_byte_strings_present`, `cr_02_direct_mode_timeout_emits_warn_macro`, `wr_04_no_pid_fallback_on_getpgid_failure`, `wr_02_no_silent_setrlimit_discards`) continue to pass unchanged.
    - After fix: If a future commit re-introduces `format!()` into either (a) the child arm or (b) `clear_close_on_exec` body, the test fails with a clear error message naming which surface regressed.
  </behavior>
  <action>
    Replace the existing `find_child_branch_lines` helper (lines 47-79) with a sentinel-based slicer, AND add a new `slice_function_body` helper, AND extend `cr_01_no_format_macro_in_post_fork_child_branch` (lines 95-128) to add the per-helper assertion.

    **Step 1 — Replace `find_child_branch_lines` (lines 43-79):**

    Delete the existing doc comment and function body for `find_child_branch_lines` (lines 43-79). Replace with:

    ```rust
    /// Find the line range of the post-fork child arm by searching for the sentinel
    /// comments `// CR-01-CHILD-ARM-START` and `// CR-01-CHILD-ARM-END`.
    ///
    /// Returns `(start_line, end_line)` (1-indexed, inclusive) — the lines BETWEEN
    /// the sentinels (not including the sentinel comments themselves).
    ///
    /// Panics if either sentinel is missing — that indicates the production code
    /// was refactored and the sentinels need to be re-placed.
    ///
    /// This replaces the previous brace-counting + first-match-find approach
    /// (WR-A + WR-B in 25-REVIEW-GAPS.md): brace counting ignored string literals
    /// and block comments; first-match-find could be silently misaimed by a
    /// future test-helper child arm added before line 844.
    fn find_child_branch_lines(src: &str) -> (usize, usize) {
        const START_SENTINEL: &str = "CR-01-CHILD-ARM-START";
        const END_SENTINEL: &str = "CR-01-CHILD-ARM-END";

        let start_byte = src.find(START_SENTINEL).unwrap_or_else(|| {
            panic!(
                "expected `{START_SENTINEL}` sentinel in exec_strategy.rs — \
                 production child arm is missing its scoping sentinel; \
                 see 25-VERIFICATION.md CR-01-RESIDUAL fix"
            )
        });
        let end_byte = src.find(END_SENTINEL).unwrap_or_else(|| {
            panic!(
                "expected `{END_SENTINEL}` sentinel in exec_strategy.rs — \
                 production child arm is missing its closing sentinel; \
                 see 25-VERIFICATION.md CR-01-RESIDUAL fix"
            )
        });
        assert!(
            end_byte > start_byte,
            "CR-01-CHILD-ARM-END must appear after CR-01-CHILD-ARM-START in source order \
             (got start={start_byte}, end={end_byte})"
        );

        // Convert byte offsets to 1-indexed line numbers. The returned range covers
        // the lines BETWEEN the two sentinels (exclusive of the sentinel lines
        // themselves), so line-comment stripping in the caller does not eat the
        // sentinels' own contents.
        let start_line = src[..start_byte].matches('\n').count() + 1;
        let end_line = src[..end_byte].matches('\n').count() + 1;
        (start_line + 1, end_line - 1)
    }
    ```

    Note the `+1`/`-1` adjustment — the returned range is *between* the sentinels (exclusive of the sentinel lines themselves), which preserves the existing test's semantics while ensuring the sentinel comments themselves are not counted in `format!(` scans.

    **Step 2 — Add `slice_function_body` helper (insert immediately after the new `find_child_branch_lines` body, before the existing `slice_lines` helper):**

    ```rust
    /// Return the body (everything between the opening `{` and matching closing `}`)
    /// of a function whose signature begins with `fn_signature_prefix`. Used for
    /// per-helper assertions (e.g. clear_close_on_exec) so the regression test can
    /// reach beyond the lexical child arm region.
    ///
    /// `fn_signature_prefix` should be a stable, unique substring of the function
    /// signature line — e.g. `"fn clear_close_on_exec(fd: i32) -> std::io::Result<()>"`.
    ///
    /// Panics if the signature is not found.
    fn slice_function_body(src: &str, fn_signature_prefix: &str) -> String {
        let sig_byte = src.find(fn_signature_prefix).unwrap_or_else(|| {
            panic!(
                "expected function signature `{fn_signature_prefix}` in exec_strategy.rs — \
                 if this helper was renamed or its signature changed, update the \
                 strengthened CR-01-RESIDUAL test in resl_nix_async_signal_safety.rs"
            )
        });
        // Locate the opening `{` after the signature.
        let body_start = src[sig_byte..]
            .find('{')
            .map(|off| sig_byte + off)
            .expect("function signature without an opening brace");

        // Brace counting is safe here because we are scanning a *small, named function*
        // body, not an arbitrary match arm. The function signature is a stable anchor;
        // string-literal/comment fragility (WR-B's concern about the broader child arm)
        // is unlikely to materialize inside this single helper. If a future commit
        // introduces a `{` inside a string literal here, the test failure will be loud.
        let bytes = src.as_bytes();
        let mut depth = 0i32;
        let mut end_byte = body_start;
        for (i, b) in bytes.iter().enumerate().skip(body_start) {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end_byte = i;
                        break;
                    }
                }
                _ => {}
            }
        }
        assert!(
            end_byte > body_start,
            "could not find matching `}}` for `{fn_signature_prefix}`"
        );
        src[body_start..=end_byte].to_string()
    }
    ```

    **Step 3 — Extend `cr_01_no_format_macro_in_post_fork_child_branch`:**

    Locate the existing test (currently lines 95-128). After the existing `assert_eq!(count, 0, ...)` block (around line 127), add the following NEW assertion block before the final closing `}` of the test function:

    ```rust
        // CR-01-RESIDUAL: clear_close_on_exec is reachable from the post-fork child
        // arm (line 950 call site). Its body must not allocate. This per-helper
        // scan closes the call-graph gap that the lexical region scan above misses.
        // See 25-VERIFICATION.md CR-01-RESIDUAL gaps.missing block, option (b).
        let helper_body = slice_function_body(
            &src,
            "fn clear_close_on_exec(fd: i32) -> std::io::Result<()>",
        );
        // Strip line comments so SAFETY/doc remarks that mention `format!(...)`
        // do not false-positive.
        let helper_stripped: String = helper_body
            .lines()
            .map(|line| match line.find("//") {
                Some(idx) => &line[..idx],
                None => line,
            })
            .collect::<Vec<_>>()
            .join("\n");
        let helper_format_count = helper_stripped.matches("format!(").count();
        assert_eq!(
            helper_format_count, 0,
            "CR-01-RESIDUAL regression: found {helper_format_count} `format!(` \
             invocation(s) inside `clear_close_on_exec` body. This helper is called \
             from the post-fork child arm of execute_supervised (line 950 call site), \
             so any heap allocation here re-opens the allocator-mutex-deadlock \
             primitive that CR-01 was supposed to eliminate.\n\
             \n\
             Replace `format!(...)` with `std::io::Error::last_os_error()` \
             (which captures errno into a stack-resident io::Error::Repr without \
             allocating). The function signature must remain `fn clear_close_on_exec(fd: i32) \
             -> std::io::Result<()>` so the call site discards the io::Error via \
             `if let Err(_e) = ...`.\n\
             \n\
             See 25-VERIFICATION.md gaps.missing block for the canonical fix."
        );
    ```

    **DO NOT modify** any of the other tests (`cr_01_and_wr_02_const_msg_byte_strings_present`, `cr_02_direct_mode_timeout_emits_warn_macro`, `wr_04_no_pid_fallback_on_getpgid_failure`, `wr_02_no_silent_setrlimit_discards`) — they remain unchanged.

    **DO NOT** add `#[allow(clippy::unwrap_used)]` at the file or test level — `panic!()` and `unwrap_or_else(|| panic!(...))` are allowed in test scaffolding code per CLAUDE.md ("Exceptions: `#[allow(clippy::unwrap_used)]` is permitted in test modules") but the existing file already uses `.expect()` and `.unwrap_or_else(|e| panic!(...))` without such an allow — match the existing style.
  </action>
  <verify>
    <automated>
      grep -c "CR-01-CHILD-ARM-START\|CR-01-CHILD-ARM-END" crates/nono-cli/tests/resl_nix_async_signal_safety.rs
      grep -c "fn slice_function_body" crates/nono-cli/tests/resl_nix_async_signal_safety.rs
      grep -c "slice_function_body" crates/nono-cli/tests/resl_nix_async_signal_safety.rs
      grep -c "fn clear_close_on_exec(fd: i32) -> std::io::Result<()>" crates/nono-cli/tests/resl_nix_async_signal_safety.rs
      grep -c "CR-01-RESIDUAL regression" crates/nono-cli/tests/resl_nix_async_signal_safety.rs
      cargo build --package nono-cli --tests 2>&1 | tail -10
      cargo test --package nono-cli --test resl_nix_async_signal_safety 2>&1 | tail -20
      cargo clippy --package nono-cli --tests -- -D warnings 2>&1 | tail -10
      cargo fmt --check --all 2>&1 | tail -10
    </automated>
  </verify>
  <acceptance_criteria>
    1. `grep -c "CR-01-CHILD-ARM-START\|CR-01-CHILD-ARM-END" crates/nono-cli/tests/resl_nix_async_signal_safety.rs` returns at least 2 (one for each sentinel name in the new `find_child_branch_lines`).
    2. `grep -c "fn slice_function_body" crates/nono-cli/tests/resl_nix_async_signal_safety.rs` returns 1 (the new helper definition).
    3. `grep -c "slice_function_body" crates/nono-cli/tests/resl_nix_async_signal_safety.rs` returns >= 2 (definition + at least one call site in cr_01_no_format_macro_in_post_fork_child_branch).
    4. `grep -c "fn clear_close_on_exec(fd: i32) -> std::io::Result<()>" crates/nono-cli/tests/resl_nix_async_signal_safety.rs` returns 1 (the signature string passed to slice_function_body).
    5. `grep -c "CR-01-RESIDUAL regression" crates/nono-cli/tests/resl_nix_async_signal_safety.rs` returns 1 (the new failure-mode assertion message).
    6. `cargo build --package nono-cli --tests` exits 0.
    7. `cargo test --package nono-cli --test resl_nix_async_signal_safety` exits 0 with all 5 tests reporting `passed` (cr_01_no_format_macro_in_post_fork_child_branch, cr_01_and_wr_02_const_msg_byte_strings_present, cr_02_direct_mode_timeout_emits_warn_macro, wr_04_no_pid_fallback_on_getpgid_failure, wr_02_no_silent_setrlimit_discards).
    8. `cargo clippy --package nono-cli --tests -- -D warnings` exits 0.
    9. `cargo fmt --check --all` exits 0.
    10. **Negative regression sanity check** (manual reasoning, not automated): If Task 2 had been skipped (clear_close_on_exec still using format!()), the new assertion would FAIL with the "CR-01-RESIDUAL regression" message — proves the test catches the original defect. Verifier: temporarily revert Task 2's change locally, re-run the test, observe failure, restore Task 2. (NOTE: this is a sanity check the executor can perform once during verification but should leave the source restored.)
  </acceptance_criteria>
  <done>find_child_branch_lines now uses sentinel-comment scoping (no brace counting on the broad arm); slice_function_body helper added for per-helper scans; cr_01_no_format_macro_in_post_fork_child_branch additionally asserts clear_close_on_exec body has zero format!() calls. All 5 tests in the file pass. Build, clippy, fmt clean.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Post-fork child arm of execute_supervised | Async-signal-unsafe context; allocator may be locked from parent thread state at fork() time. Any heap allocation here can deadlock. |
| `clear_close_on_exec` helper called from the child arm | Was previously crossing the boundary by calling `format!()` on its fcntl error paths — re-opens the deadlock primitive. |
| Static-analysis regression test scope | Was previously fragile (first-match-find, brace-count without literal/comment awareness); a future refactor could silently misaim the scan. |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-25-05-01 | Denial of Service (deadlock) | `clear_close_on_exec` called from post-fork child on fcntl failure | mitigate | Task 2: Convert to `std::io::Result<()>` with `std::io::Error::last_os_error()` (stack-resident `io::Error::Repr` for raw OS errors — does not allocate). |
| T-25-05-02 | Tampering (test scaffolding silently misaimed) | `find_child_branch_lines` first-match-find + brace-count fragility (WR-A + WR-B) | mitigate | Task 1 + Task 3: Sentinel-comment scoping (`// CR-01-CHILD-ARM-START` / `// CR-01-CHILD-ARM-END`) replaces `src.find()` first-match and brace counting. The sentinels are self-documenting and cannot be silently bypassed by a future child-arm reordering. |
| T-25-05-03 | Repudiation (regression test passes over an exploitable defect) | Static-analysis test scoping the wrong region or only the lexical region | mitigate | Task 3: Adds an explicit per-helper assertion that scans the body of `clear_close_on_exec` for `format!()` calls — closes the call-graph gap without committing to full reachability analysis (Sandbox::apply etc. remain explicitly out of scope per CONTEXT.md and VERIFICATION.md). |
| T-25-05-04 | Defense-in-depth bypass | Future maintainer adds a `format!()` to a different reachable helper (e.g. install_seccomp_notify, send_fd_via_socket) | accept | Out of scope this cycle. The 25-VERIFICATION.md `missing` block scopes this fix to clear_close_on_exec only; the architectural inconsistency about Sandbox::apply allocations is documented in 25-03-SUMMARY and accepted under the threading-context contract. Future hardening would expand scope significantly and is gated on a separate ADR. |
</threat_model>

<verification>
After all three tasks:

```bash
# Task 1: sentinel comments present
grep -c "CR-01-CHILD-ARM-START" crates/nono-cli/src/exec_strategy.rs    # Expected: 1
grep -c "CR-01-CHILD-ARM-END" crates/nono-cli/src/exec_strategy.rs      # Expected: 1

# Task 2: clear_close_on_exec converted
grep -c "fn clear_close_on_exec(fd: i32) -> std::io::Result<()>" crates/nono-cli/src/exec_strategy.rs   # Expected: 1
awk '/^fn clear_close_on_exec/,/^\}/' crates/nono-cli/src/exec_strategy.rs | grep -c "format!"          # Expected: 0
awk '/^fn clear_close_on_exec/,/^\}/' crates/nono-cli/src/exec_strategy.rs | grep -c "last_os_error"   # Expected: 2
awk '/^fn clear_close_on_exec/,/^\}/' crates/nono-cli/src/exec_strategy.rs | grep -c "NonoError"        # Expected: 0
grep -n "if let Err(_e) = clear_close_on_exec" crates/nono-cli/src/exec_strategy.rs                     # Expected: 1 match (call site untouched)

# Task 3: regression test strengthened
grep -c "CR-01-CHILD-ARM-START\|CR-01-CHILD-ARM-END" crates/nono-cli/tests/resl_nix_async_signal_safety.rs  # Expected: >=2
grep -c "fn slice_function_body" crates/nono-cli/tests/resl_nix_async_signal_safety.rs                       # Expected: 1
grep -c "CR-01-RESIDUAL regression" crates/nono-cli/tests/resl_nix_async_signal_safety.rs                   # Expected: 1

# All regression tests pass (5 tests in the file)
cargo test --package nono-cli --test resl_nix_async_signal_safety
# Expected: "test result: ok. 5 passed; 0 failed"

# Existing helper unit test still passes
cargo test --package nono-cli test_clear_close_on_exec_clears_flag
# Expected: "test result: ok. 1 passed"

# Workspace-wide build + lint + fmt
cargo build --workspace
cargo clippy --workspace -- -D warnings -D clippy::unwrap_used
cargo fmt --check --all

# D-19 / D-21 byte-identical Windows preservation invariant
git diff --stat HEAD~3 HEAD -- crates/nono-cli/src/exec_strategy_windows/ crates/nono/src/sandbox/windows.rs
# Expected: empty output (no Windows-side files touched by this plan)
```
</verification>

<success_criteria>
- `clear_close_on_exec` returns `std::io::Result<()>` and uses `std::io::Error::last_os_error()` on both fcntl error paths (zero `format!()` in body, zero `NonoError::SandboxInit` in body).
- Two sentinel comments (`// CR-01-CHILD-ARM-START` and `// CR-01-CHILD-ARM-END`) bracket ONLY the production child arm body in `exec_strategy.rs` (not the test-helper child arms at 3551 / 3647).
- `find_child_branch_lines` in the regression test uses sentinel-comment scoping (no `src.find("Ok(ForkResult::Child) => {")` first-match, no brace counting on the broad arm).
- A new `slice_function_body` helper exists and is used to scope a per-helper assertion targeting `clear_close_on_exec`.
- `cr_01_no_format_macro_in_post_fork_child_branch` asserts BOTH (a) zero `format!(` in the sentinel-scoped child arm region, AND (b) zero `format!(` in the body of `clear_close_on_exec`.
- All 5 tests in `crates/nono-cli/tests/resl_nix_async_signal_safety.rs` pass.
- The existing `test_clear_close_on_exec_clears_flag` unit test in `exec_strategy.rs` continues to pass against the new signature.
- `cargo build --workspace` exits 0.
- `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` exits 0.
- `cargo fmt --check --all` exits 0.
- D-19 / D-21 invariant: `git diff --stat HEAD~N HEAD -- crates/nono-cli/src/exec_strategy_windows/ crates/nono/src/sandbox/windows.rs` is empty across this plan's commits.
</success_criteria>

<output>
After completion, create `.planning/phases/25-cross-platform-resl-aipc-unix-design/25-05-RESL-NIX-CR01-RESIDUAL-SUMMARY.md`
</output>
