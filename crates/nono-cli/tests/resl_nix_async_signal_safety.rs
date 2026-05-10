//! Phase 25-03 / CR-01 regression: post-fork child branch must be async-signal-safe.
//!
//! The child branch of `execute_supervised` (between `Ok(ForkResult::Child)` and the
//! final `_exit(127)`) runs in a state where heap allocation is unsafe:
//! after `fork()` in a multi-threaded program, the child inherits whatever lock state
//! the parent's allocator held at the moment of `fork()`. If the parent thread held
//! the allocator mutex, the child inherits a locked mutex and any subsequent heap
//! allocation deadlocks.
//!
//! `format!()` allocates a `String` on the heap. So does any code path that goes
//! through `String`, `Vec::new()` followed by `push`, etc. The async-signal-safe
//! pattern is to use a pre-allocated `const MSG: &[u8]` static byte string and call
//! `libc::write` + `libc::_exit` directly — both are POSIX async-signal-safe.
//!
//! This test scans the source of `crates/nono-cli/src/exec_strategy.rs` and asserts:
//!   1. Within the lexical region of the `Ok(ForkResult::Child)` arm, there are zero
//!      `format!(` invocations.
//!   2. The child branch contains at least the expected number of `const MSG_*: &[u8]`
//!      static byte strings used for error reporting.
//!
//! This is a structural / static-analysis regression — it cannot detect runtime
//! deadlocks (those require a deliberate test of fork-while-allocator-locked, which
//! is platform-specific and inherently flaky), but it does detect the introduction
//! of any new `format!()` call into the child branch in code review long before
//! such a test would be possible.
//!
//! Located in the workspace tests because exec_strategy.rs is `#[cfg(unix)]` only,
//! but the source-text check works on any platform — we just read the file as text.

use std::path::PathBuf;

/// Read `crates/nono-cli/src/exec_strategy.rs` from the workspace.
fn read_exec_strategy() -> String {
    // CARGO_MANIFEST_DIR points at the nono-cli crate root.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let path = PathBuf::from(manifest_dir)
        .join("src")
        .join("exec_strategy.rs");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

/// Find the byte range of the `Ok(ForkResult::Child) => {` arm by counting braces.
///
/// Returns `(start_line, end_line)` (1-indexed, inclusive). Panics if the marker is
/// not found — that would indicate a refactor we want to know about.
fn find_child_branch_lines(src: &str) -> (usize, usize) {
    let marker = "Ok(ForkResult::Child) => {";
    let start_byte = src
        .find(marker)
        .expect("expected `Ok(ForkResult::Child) => {` marker in exec_strategy.rs");

    // Count braces from the opening `{` of the arm body.
    let body_start = start_byte + marker.len() - 1; // index of the `{`
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
        "could not find matching `}}` for child branch arm body"
    );

    let start_line = src[..start_byte].matches('\n').count() + 1;
    let end_line = src[..end_byte].matches('\n').count() + 1;
    (start_line, end_line)
}

/// Extract the substring of `src` covering the lexical region `[start_line..=end_line]`
/// (1-indexed, inclusive).
fn slice_lines(src: &str, start_line: usize, end_line: usize) -> String {
    src.lines()
        .enumerate()
        .filter(|(i, _)| {
            let lineno = i + 1;
            lineno >= start_line && lineno <= end_line
        })
        .map(|(_, l)| l)
        .collect::<Vec<_>>()
        .join("\n")
}

/// CR-01: zero `format!(` invocations inside the post-fork child branch.
#[test]
fn cr_01_no_format_macro_in_post_fork_child_branch() {
    let src = read_exec_strategy();
    let (start, end) = find_child_branch_lines(&src);
    let region = slice_lines(&src, start, end);

    // Strip line comments so a comment that mentions `format!(...)` (e.g. in a
    // SAFETY rationale or doc remark) doesn't false-positive the test.
    let stripped: String = region
        .lines()
        .map(|line| match line.find("//") {
            Some(idx) => &line[..idx],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n");

    let count = stripped.matches("format!(").count();
    assert_eq!(
        count, 0,
        "CR-01 regression: found {count} `format!(` invocation(s) in the post-fork \
         child branch of execute_supervised (lines {start}..={end} of \
         crates/nono-cli/src/exec_strategy.rs).\n\
         \n\
         The child branch runs in async-signal-unsafe context — `format!()` allocates \
         on the heap and can deadlock if the parent held the allocator mutex at fork() \
         time. Replace each `format!()` with a `const MSG_*: &[u8] = b\"...\\n\";` \
         static byte string written via `libc::write(libc::STDERR_FILENO, ...)`.\n\
         \n\
         See the already-correct chdir handler near the bottom of the child arm for \
         the reference pattern."
    );
}

/// CR-01 / WR-02: at least 11 `const MSG_*: &[u8]` declarations in the file
/// (9 from CR-01 child-branch sites + 2 from WR-02 rlimit-failure handlers).
///
/// This is a structural assertion that the consts WERE introduced rather than the
/// `format!()` calls being silently removed without a replacement.
#[test]
fn cr_01_and_wr_02_const_msg_byte_strings_present() {
    let src = read_exec_strategy();
    // Match `const MSG_<NAME>: &[u8]` declarations (any uppercase suffix).
    let count = src
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            // Cheap check: starts with `const MSG_` and contains `: &[u8]`.
            t.starts_with("const MSG_") && t.contains(": &[u8]")
        })
        .count();
    assert!(
        count >= 11,
        "expected at least 11 `const MSG_*: &[u8]` declarations in exec_strategy.rs \
         (9 for CR-01 child-branch sites + 2 for WR-02 rlimit-failure handlers); \
         found {count}.\n\
         \n\
         Each `format!()` removed for CR-01 must be replaced with a named static \
         byte string declared immediately before the `unsafe` block that uses it. \
         See the plan 25-03 task action for the canonical names \
         (MSG_CGROUP, MSG_SOCK, MSG_SANDBOX_LINUX, MSG_SANDBOX_OTHER, \
         MSG_SECCOMP_SEND, MSG_SECCOMP_FAIL, MSG_PROXY_SEND, MSG_PROXY_FAIL, \
         MSG_DUMPABLE, MSG_RLIMIT_AS_FAIL, MSG_RLIMIT_NPROC_FAIL)."
    );
}

/// CR-02: `--timeout` in Direct mode must surface a `warn!` invocation that names
/// the limitation. The doc comment in `execute_direct` mentions the same phrase, so
/// the assertion targets the macro invocation specifically (`warn!(...)`).
#[test]
fn cr_02_direct_mode_timeout_emits_warn_macro() {
    let src = read_exec_strategy();
    let mut found_warn = false;
    let mut found_eprintln = false;
    // Walk the file with a small window so a multi-line warn!(...) call counts.
    let bytes = src.as_bytes();
    let needle_warn = b"warn!(";
    let needle_eprintln = b"eprintln!(";
    let mut i = 0usize;
    while i + needle_warn.len() < bytes.len() {
        if &bytes[i..i + needle_warn.len()] == needle_warn {
            // Look at the next ~200 bytes for `timeout` and `not enforced`.
            let end = (i + 400).min(bytes.len());
            let window = &src[i..end];
            if window.contains("timeout") && window.contains("not enforced") {
                found_warn = true;
            }
        }
        if i + needle_eprintln.len() < bytes.len()
            && &bytes[i..i + needle_eprintln.len()] == needle_eprintln
        {
            let end = (i + 400).min(bytes.len());
            let window = &src[i..end];
            if window.contains("--strategy supervised") {
                found_eprintln = true;
            }
        }
        i += 1;
    }
    assert!(
        found_warn,
        "CR-02 regression: expected a `warn!(...)` invocation in exec_strategy.rs \
         whose body mentions both `timeout` and `not enforced`. The doc comment \
         in execute_direct that mentions `--timeout is NOT enforced in Direct mode` \
         is plain text, not a macro invocation, and does not satisfy this check."
    );
    assert!(
        found_eprintln,
        "CR-02 regression: expected an `eprintln!(...)` invocation in exec_strategy.rs \
         whose body mentions `--strategy supervised`. The user-visible warning to \
         stderr must fire even when `RUST_LOG` is not set."
    );
}

/// WR-04: no `unwrap_or(child)` PID fallback inside the macOS watchdog spawn.
/// The replacement is a `match getpgid(...)` that returns `None` on `Err`.
#[test]
fn wr_04_no_pid_fallback_on_getpgid_failure() {
    let src = read_exec_strategy();
    assert!(
        !src.contains("unwrap_or(child)"),
        "WR-04 regression: found `unwrap_or(child)` in exec_strategy.rs. \
         Falling back to the child PID as the process group target is unsafe under \
         PID reuse — `kill(-child_pid, SIGKILL)` could target an unrelated process \
         group. Replace with a `match getpgid(Some(child)) {{ Ok(pgrp) => ..., \
         Err(e) => {{ warn!(...); None }} }}` and let the watchdog be skipped on Err."
    );
    assert!(
        src.contains("match getpgid("),
        "WR-04 regression: expected a `match getpgid(...)` arm in exec_strategy.rs \
         (replacing the `unwrap_or(child)` PID fallback)."
    );
}

/// WR-02: no silent `let _ = setrlimit(...)` discards in exec_strategy.rs.
#[test]
fn wr_02_no_silent_setrlimit_discards() {
    let src = read_exec_strategy();
    let count = src.matches("let _ = setrlimit").count();
    assert_eq!(
        count, 0,
        "WR-02 regression: found {count} silent `let _ = setrlimit(...)` discard(s) \
         in exec_strategy.rs. Each setrlimit failure in the post-fork child must be \
         fail-closed (`MSG_RLIMIT_*_FAIL` static + `_exit(126)`)."
    );
}
