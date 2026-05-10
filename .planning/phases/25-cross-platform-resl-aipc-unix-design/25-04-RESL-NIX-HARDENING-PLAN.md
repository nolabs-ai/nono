---
phase: 25-cross-platform-resl-aipc-unix-design
plan: 04
type: execute
wave: 1
depends_on: []
files_modified:
  - crates/nono-cli/src/exec_strategy/supervisor_linux.rs
  - crates/nono-cli/src/exec_strategy/supervisor_macos.rs
autonomous: true
gap_closure: true
addresses: [WR-03, WR-02, WR-04, WR-05]
requirements: [REQ-RESL-NIX-01, REQ-RESL-NIX-03]

must_haves:
  truths:
    - "CgroupSession::detect_from_str rejects cgroup-relative paths containing .. components with NonoError::UnsupportedPlatform"
    - "setrlimit failures in the execute_supervised macOS child branch cause _exit(126) with a static message, not silent discard"
    - "getpgid failure in spawn_macos_timeout_watchdog logs a warning and returns without sending SIGKILL (no PID fallback)"
    - "nix::errno::Errno-to-io::Error conversion in supervisor_macos.rs uses std::io::Error::from(e) not e as i32"
  artifacts:
    - path: "crates/nono-cli/src/exec_strategy/supervisor_linux.rs"
      provides: "Path traversal guard in detect_from_str; regression test for .. injection"
      contains: "starts_with(\"/sys/fs/cgroup\")"
    - path: "crates/nono-cli/src/exec_strategy/supervisor_macos.rs"
      provides: "Fail-closed setrlimit; no PID fallback in getpgid; idiomatic errno conversion"
      contains: "std::io::Error::from"
  key_links:
    - from: "CgroupSession::detect_from_str"
      to: "NonoError::UnsupportedPlatform"
      via: "abs_path.starts_with(\"/sys/fs/cgroup\") guard after PathBuf::join"
      pattern: "starts_with.*sys/fs/cgroup"
    - from: "execute_supervised macOS child setrlimit"
      to: "libc::_exit(126)"
      via: "is_err() check on setrlimit return value"
      pattern: "MSG_RLIMIT.*_exit\\(126\\)"
    - from: "spawn_macos_timeout_watchdog caller"
      to: "skip kill on getpgid Err"
      via: "match getpgid(Some(child)) { Ok(pgrp) => ..., Err(_) => { warn!; return; } }"
      pattern: "getpgid.*Err.*warn"
---

<objective>
Fix three code-review warnings (WR-03, WR-02, WR-04, WR-05) split across the two platform supervisor modules:

- **WR-03** (`supervisor_linux.rs`): `CgroupSession::detect_from_str` constructs the cgroup path from `/proc/self/cgroup` content without verifying the result stays under `/sys/fs/cgroup`. An attacker-controlled cgroup entry with `..` components could redirect path construction. Add `Path::starts_with("/sys/fs/cgroup")` validation after the join, and add a unit regression test.

- **WR-02** (`supervisor_macos.rs` via `exec_strategy.rs` macOS child branch): `setrlimit` calls in the supervised-child branch use `let _ = setrlimit(...)` — errors are silently discarded. If the system hard limit is below the requested value, the sandbox runs without `--max-processes` enforcement. Convert to fail-closed: on error, write a static diagnostic and `_exit(126)`.

- **WR-04** (`exec_strategy.rs` macOS watchdog call site): `getpgid(Some(child)).unwrap_or(child)` falls back to the child PID as process group. Under PID reuse, `kill(-pgrp, SIGKILL)` could target the wrong process group. Replace with a `match` that logs and skips the kill on `Err`.

- **WR-05** (`supervisor_macos.rs`): `map_err(|e| std::io::Error::from_raw_os_error(e as i32))` relies on `nix::errno::Errno` being `#[repr(i32)]`. Use the public `From<Errno> for std::io::Error` impl instead: `map_err(std::io::Error::from)`.

Purpose: Harden the Linux cgroup path construction against traversal; eliminate silent security-degradation in macOS setrlimit; remove unsafe PID fallback in watchdog; use idiomatic errno conversion.

Output: Modified `supervisor_linux.rs` and `supervisor_macos.rs` with all four warnings addressed. New unit test for WR-03.
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
<!-- From supervisor_linux.rs: detect_from_str (lines 880–908) -->
```rust
pub(crate) fn detect_from_str(contents: &str) -> Result<PathBuf> {
    // ... validates 0:: prefix ...
    let abs_path = PathBuf::from("/sys/fs/cgroup")
        .join(cgroup_rel.trim_start_matches('/').trim_end_matches('/'));
    Ok(abs_path)   // <-- WR-03: no Path::starts_with check here
}
```

<!-- From supervisor_macos.rs: install_pre_exec (lines 106–128) -->
```rust
unsafe {
    cmd.pre_exec(move || -> std::io::Result<()> {
        use nix::sys::resource::{setrlimit, Resource};
        if let Some(bytes) = memory_bytes {
            let limit = bytes.try_into().unwrap_or(nix::libc::rlim_t::MAX);
            setrlimit(Resource::RLIMIT_AS, limit, limit)
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;  // WR-05
        }
        if let Some(n) = max_processes {
            let limit = u64::from(n);
            setrlimit(Resource::RLIMIT_NPROC, limit, limit)
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;  // WR-05
        }
        Ok(())
    });
}
```

<!-- From exec_strategy.rs macOS child branch (lines ~877–891): -->
```rust
#[cfg(target_os = "macos")]
if macos_resource_limits.is_some() {
    use nix::sys::resource::{setrlimit, Resource};
    if let Some(bytes) = resource_limits.memory_bytes {
        let limit: nix::libc::rlim_t = bytes.try_into().unwrap_or(nix::libc::rlim_t::MAX);
        let _ = setrlimit(Resource::RLIMIT_AS, limit, limit);     // WR-02: silent discard
    }
    if let Some(n) = resource_limits.max_processes {
        let limit = u64::from(n);
        let _ = setrlimit(Resource::RLIMIT_NPROC, limit, limit);  // WR-02: silent discard
    }
}
```

<!-- From exec_strategy.rs macOS watchdog spawn (lines ~1292–1302): -->
```rust
#[cfg(target_os = "macos")]
let _timeout_watchdog = timeout_deadline
    .map(|deadline| {
        use nix::unistd::getpgid;
        let child_pgrp = getpgid(Some(child)).unwrap_or(child);  // WR-04: PID fallback
        let fired = timeout_fired.clone();
        Some(supervisor_macos::spawn_macos_timeout_watchdog(
            deadline, child_pgrp, fired,
        ))
    })
    .flatten();
```

<!-- NonoError variants available for use: -->
```rust
// From crates/nono/src/error.rs:
NotSupportedOnPlatform { feature: String },
UnsupportedPlatform(String),
SandboxInit(String),
```
</interfaces>
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1: Add Path::starts_with guard in detect_from_str + regression test (WR-03)</name>
  <files>crates/nono-cli/src/exec_strategy/supervisor_linux.rs</files>
  <read_first>
    - crates/nono-cli/src/exec_strategy/supervisor_linux.rs (lines 875–945: detect_from_str and detect, plus existing test module at line 638)
    - 25-REVIEW.md WR-03 section for the exact fix pattern required
    - CLAUDE.md §Path Handling for the mandate: "Always use path component comparison, not string operations. String starts_with() on paths is a vulnerability."
  </read_first>
  <behavior>
    - After fix: `detect_from_str("0::/../../etc")` returns `Err(NonoError::UnsupportedPlatform(...))` with message containing "path traversal"
    - After fix: `detect_from_str("0::/user.slice/session-1.scope")` still returns `Ok(PathBuf)` with path `/sys/fs/cgroup/user.slice/session-1.scope` (normal case unaffected)
    - After fix: a unit test `cgroup_path_rejects_parent_dir_traversal` exists in the `#[cfg(test)] mod tests` block and calls `CgroupSession::detect_from_str` with a malicious input
    - After fix: a unit test `cgroup_path_accepts_normal_path` exists to confirm normal operation
  </behavior>
  <action>
    **Step 1 — Add the guard in detect_from_str:**

    After the `let abs_path = PathBuf::from("/sys/fs/cgroup").join(...)` line (currently the last line before `Ok(abs_path)`), add:

    ```rust
    // WR-03: Validate the constructed path stays within /sys/fs/cgroup.
    // Path::starts_with performs component-level comparison, so
    // "/sys/fs/cgroupevil" does NOT match — only proper children do.
    // A malicious /proc/self/cgroup entry with ".." components (e.g.,
    // "0::/../../etc") would produce an abs_path that escapes the cgroup root.
    if !abs_path.starts_with("/sys/fs/cgroup") {
        return Err(NonoError::UnsupportedPlatform(format!(
            "cgroup_v2: constructed cgroup path {abs_path:?} escapes /sys/fs/cgroup \
             (path traversal detected in /proc/self/cgroup content)"
        )));
    }
    ```

    The final `detect_from_str` body (after the fix) should end with:
    ```rust
    if !abs_path.starts_with("/sys/fs/cgroup") {
        return Err(NonoError::UnsupportedPlatform(format!(
            "cgroup_v2: constructed cgroup path {abs_path:?} escapes /sys/fs/cgroup \
             (path traversal detected in /proc/self/cgroup content)"
        )));
    }
    Ok(abs_path)
    ```

    **Step 2 — Add regression tests in the existing #[cfg(test)] mod tests block:**

    Append to the existing `tests` module at the bottom of the file:

    ```rust
    #[test]
    fn cgroup_path_rejects_parent_dir_traversal() {
        // Attacker-controlled /proc/self/cgroup with .. to escape /sys/fs/cgroup
        let err = CgroupSession::detect_from_str("0::/../../etc")
            .expect_err("must reject path traversal");
        match err {
            NonoError::UnsupportedPlatform(msg) => {
                assert!(
                    msg.contains("path traversal") || msg.contains("escapes"),
                    "error message must mention traversal, got: {msg}"
                );
            }
            other => panic!("expected UnsupportedPlatform, got: {other:?}"),
        }
    }

    #[test]
    fn cgroup_path_rejects_encoded_traversal() {
        // Variant: leading .. after trim_start_matches strips the slash
        let err = CgroupSession::detect_from_str("0::/../../../proc/self")
            .expect_err("must reject path traversal with leading slash");
        assert!(matches!(err, NonoError::UnsupportedPlatform(_)));
    }

    #[test]
    fn cgroup_path_accepts_normal_path() {
        // Normal systemd-delegated cgroup path must still work
        let result = CgroupSession::detect_from_str("0::/user.slice/user-1000.slice/session-1.scope");
        // We cannot verify the path exists on this host, but construction must succeed
        // (detect_from_str does NOT check fs existence — that is detect()'s job).
        // Confirm the returned path starts with /sys/fs/cgroup.
        let path = result.expect("normal cgroup path must be accepted");
        assert!(
            path.starts_with("/sys/fs/cgroup"),
            "path must be under /sys/fs/cgroup, got: {path:?}"
        );
    }
    ```

    Note: the test module already has `#[allow(clippy::unwrap_used)]` per the existing tests pattern — do NOT add `#[allow(dead_code)]`. The tests use `expect_err` / `expect` which are allowed in tests (CLAUDE.md: "permitted in test modules").

    The `CgroupSession::detect_from_str` function is `pub(crate)`, so the in-module `use super::*` in the test module already brings it into scope.
  </action>
  <verify>
    <automated>
      grep -n "starts_with.*sys/fs/cgroup" crates/nono-cli/src/exec_strategy/supervisor_linux.rs
      grep -n "cgroup_path_rejects_parent_dir_traversal\|cgroup_path_accepts_normal_path\|cgroup_path_rejects_encoded" crates/nono-cli/src/exec_strategy/supervisor_linux.rs
      cargo test --package nono-cli cgroup_path_rejects_parent_dir_traversal 2>&1 | tail -10
      cargo test --package nono-cli cgroup_path_accepts_normal_path 2>&1 | tail -10
      cargo test --package nono-cli cgroup_path_rejects_encoded_traversal 2>&1 | tail -10
    </automated>
  </verify>
  <acceptance_criteria>
    1. `grep -c "starts_with.*sys/fs/cgroup" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` returns at least 1 (the new guard in detect_from_str) — note: this uses Path::starts_with called on a PathBuf, so the literal in source is `.starts_with("/sys/fs/cgroup")`.
    2. `grep -c "cgroup_path_rejects_parent_dir_traversal" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` returns 1.
    3. `grep -c "cgroup_path_accepts_normal_path" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` returns 1.
    4. `cargo test --package nono-cli cgroup_path_rejects_parent_dir_traversal` exits 0 (test passes).
    5. `cargo test --package nono-cli cgroup_path_accepts_normal_path` exits 0 (test passes).
    6. `cargo clippy --package nono-cli -- -D warnings -D clippy::unwrap_used` exits 0.
  </acceptance_criteria>
  <done>detect_from_str rejects paths with .. traversal via Path::starts_with guard. Three regression tests pass. Clippy clean.</done>
</task>

<task type="auto">
  <name>Task 2: Harden macOS setrlimit (WR-02), getpgid fallback (WR-04), and errno conversion (WR-05)</name>
  <files>
    crates/nono-cli/src/exec_strategy/supervisor_macos.rs
    crates/nono-cli/src/exec_strategy.rs
  </files>
  <read_first>
    - crates/nono-cli/src/exec_strategy/supervisor_macos.rs (lines 97–130: install_pre_exec; lines 158–179: spawn_macos_timeout_watchdog)
    - crates/nono-cli/src/exec_strategy.rs (lines ~875–891: macOS child branch setrlimit; lines ~1292–1302: macOS watchdog spawn)
    - 25-REVIEW.md WR-02, WR-04, WR-05 sections for exact fix patterns
  </read_first>
  <action>
    Apply three independent fixes. Each is small and targeted.

    ---

    **Fix WR-05 first (supervisor_macos.rs install_pre_exec) — idiomatic errno conversion:**

    In `MacosResourceLimits::install_pre_exec`, replace both occurrences of:
    ```rust
    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
    ```
    with:
    ```rust
    .map_err(std::io::Error::from)?;
    ```

    This uses `nix`'s public `From<Errno> for std::io::Error` impl instead of casting the internal `#[repr(i32)]`. Apply to BOTH the `RLIMIT_AS` call (line ~114) and the `RLIMIT_NPROC` call (line ~119).

    Also update the SAFETY doc comment above `install_pre_exec` (line ~90): change the sentence:
    ```
    /// The `nix::errno::Errno` → `std::io::Error` conversion uses
    /// `std::io::Error::from_raw_os_error` which is also safe in `pre_exec`.
    ```
    to:
    ```
    /// The `nix::errno::Errno` → `std::io::Error` conversion uses
    /// `std::io::Error::from` (nix's public `From<Errno>` impl) which is
    /// also safe in `pre_exec`.
    ```

    ---

    **Fix WR-02 (exec_strategy.rs macOS child branch) — fail-closed setrlimit:**

    In `execute_supervised`, locate the `#[cfg(target_os = "macos")]` block that currently does:
    ```rust
    if macos_resource_limits.is_some() {
        use nix::sys::resource::{setrlimit, Resource};
        if let Some(bytes) = resource_limits.memory_bytes {
            let limit: nix::libc::rlim_t = bytes.try_into().unwrap_or(nix::libc::rlim_t::MAX);
            let _ = setrlimit(Resource::RLIMIT_AS, limit, limit);
        }
        if let Some(n) = resource_limits.max_processes {
            let limit = u64::from(n);
            let _ = setrlimit(Resource::RLIMIT_NPROC, limit, limit);
        }
    }
    ```

    Replace it with:
    ```rust
    #[cfg(target_os = "macos")]
    if macos_resource_limits.is_some() {
        use nix::sys::resource::{setrlimit, Resource};
        if let Some(bytes) = resource_limits.memory_bytes {
            // T-25-01-05: guard against overflow on 32-bit.
            let limit: nix::libc::rlim_t = bytes.try_into().unwrap_or(nix::libc::rlim_t::MAX);
            // WR-02: fail closed — if setrlimit fails the sandbox MUST NOT continue
            // without the requested --memory enforcement.
            if setrlimit(Resource::RLIMIT_AS, limit, limit).is_err() {
                const MSG_RLIMIT_AS: &[u8] = b"nono: setrlimit(RLIMIT_AS) failed; aborting child\n";
                // SAFETY: write and _exit are async-signal-safe; we are in the
                // post-fork child branch.
                unsafe {
                    libc::write(
                        libc::STDERR_FILENO,
                        MSG_RLIMIT_AS.as_ptr().cast::<libc::c_void>(),
                        MSG_RLIMIT_AS.len(),
                    );
                    libc::_exit(126);
                }
            }
        }
        if let Some(n) = resource_limits.max_processes {
            let limit = u64::from(n);
            // WR-02: fail closed — if setrlimit fails the sandbox MUST NOT continue
            // without the requested --max-processes enforcement.
            if setrlimit(Resource::RLIMIT_NPROC, limit, limit).is_err() {
                const MSG_RLIMIT_NPROC: &[u8] =
                    b"nono: setrlimit(RLIMIT_NPROC) failed; aborting child\n";
                // SAFETY: write and _exit are async-signal-safe.
                unsafe {
                    libc::write(
                        libc::STDERR_FILENO,
                        MSG_RLIMIT_NPROC.as_ptr().cast::<libc::c_void>(),
                        MSG_RLIMIT_NPROC.len(),
                    );
                    libc::_exit(126);
                }
            }
        }
    }
    ```

    Note: This block is in the child branch of `execute_supervised`, where `format!()` is now forbidden (per Plan 25-03 Task 1). The const static byte strings are consistent with the CR-01 fix already applied.

    ---

    **Fix WR-04 (exec_strategy.rs macOS watchdog spawn) — no PID fallback on getpgid failure:**

    Locate the `#[cfg(target_os = "macos")]` watchdog spawn block that currently does:
    ```rust
    #[cfg(target_os = "macos")]
    let _timeout_watchdog = timeout_deadline
        .map(|deadline| {
            use nix::unistd::getpgid;
            let child_pgrp = getpgid(Some(child)).unwrap_or(child);
            let fired = timeout_fired.clone();
            Some(supervisor_macos::spawn_macos_timeout_watchdog(
                deadline, child_pgrp, fired,
            ))
        })
        .flatten();
    ```

    Replace with:
    ```rust
    #[cfg(target_os = "macos")]
    let _timeout_watchdog = timeout_deadline
        .map(|deadline| {
            use nix::unistd::getpgid;
            // WR-04: Do NOT fall back to child PID on getpgid failure.
            // If the child has already exited and its PID was reused, falling
            // back to kill(-child_pid, SIGKILL) could target the wrong process
            // group. Instead: if getpgid fails, log and skip the kill entirely.
            match getpgid(Some(child)) {
                Ok(child_pgrp) => {
                    let fired = timeout_fired.clone();
                    Some(supervisor_macos::spawn_macos_timeout_watchdog(
                        deadline, child_pgrp, fired,
                    ))
                }
                Err(e) => {
                    warn!(
                        "getpgid({}) failed ({}); skipping timeout watchdog — \
                         child may have already exited",
                        child.as_raw(),
                        e
                    );
                    None
                }
            }
        })
        .flatten();
    ```
  </action>
  <verify>
    <automated>
      grep -n "from_raw_os_error" crates/nono-cli/src/exec_strategy/supervisor_macos.rs
      grep -n "unwrap_or(child)" crates/nono-cli/src/exec_strategy.rs
      grep -n "MSG_RLIMIT_AS\|MSG_RLIMIT_NPROC" crates/nono-cli/src/exec_strategy.rs
      grep -n "getpgid.*Err\|Err.*getpgid\|skipping timeout watchdog" crates/nono-cli/src/exec_strategy.rs
      cargo build --workspace 2>&1 | tail -20
      cargo clippy --workspace -- -D warnings -D clippy::unwrap_used 2>&1 | tail -20
      cargo fmt --check --all 2>&1 | tail -10
    </automated>
  </verify>
  <acceptance_criteria>
    1. `grep -c "from_raw_os_error" crates/nono-cli/src/exec_strategy/supervisor_macos.rs` returns 0 (WR-05 removed both occurrences).
    2. `grep -c "map_err(std::io::Error::from)" crates/nono-cli/src/exec_strategy/supervisor_macos.rs` returns 2 (one per setrlimit call in install_pre_exec).
    3. `grep -c "MSG_RLIMIT_AS\|MSG_RLIMIT_NPROC" crates/nono-cli/src/exec_strategy.rs` returns 2 (one per setrlimit site in macOS child branch).
    4. `grep -c "let _ = setrlimit" crates/nono-cli/src/exec_strategy.rs` returns 0 (no silent discards remain in the supervised child branch).
    5. `grep -c "unwrap_or(child)" crates/nono-cli/src/exec_strategy.rs` returns 0 (WR-04 PID fallback removed).
    6. `grep -c "skipping timeout watchdog" crates/nono-cli/src/exec_strategy.rs` returns 1 (the new warn! log).
    7. `cargo build --workspace` exits 0.
    8. `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` exits 0.
    9. `cargo fmt --check --all` exits 0.
  </acceptance_criteria>
  <done>WR-05 errno conversion is idiomatic; WR-02 setrlimit is fail-closed; WR-04 getpgid match skips kill on Err. Build, clippy, fmt all pass.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| /proc/self/cgroup content → PathBuf construction | Kernel-provided but potentially attacker-influenced in container escape scenarios |
| child process → setrlimit enforcement | Enforcement fails silently without WR-02 fix, violating "fail secure" |
| child PID space → SIGKILL target | PID reuse risk when getpgid fallback sends kill to wrong group |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-25-04-01 | Elevation of Privilege | CgroupSession::detect_from_str path construction | mitigate | WR-03: Add `abs_path.starts_with("/sys/fs/cgroup")` using Path component comparison (not string starts_with), return Err on mismatch |
| T-25-04-02 | Elevation of Privilege | macOS setrlimit silent failure | mitigate | WR-02: Convert `let _ = setrlimit(...)` to fail-closed: write static diagnostic + _exit(126) on failure, consistent with Linux cgroup placement failure handling |
| T-25-04-03 | Spoofing | macOS SIGKILL to wrong process group via PID reuse | mitigate | WR-04: Match on getpgid Result; skip kill on Err — no fallback to child PID; log warning so operator knows watchdog was skipped |
| T-25-04-04 | Tampering | nix Errno internal repr change | mitigate | WR-05: Use public From<Errno> for io::Error impl instead of `e as i32` cast; eliminates silent breakage if nix changes repr |
</threat_model>

<verification>
After both tasks:

```bash
# WR-03: traversal guard present
grep -n "starts_with.*sys/fs/cgroup" crates/nono-cli/src/exec_strategy/supervisor_linux.rs
# Expected: at least 1 line in detect_from_str

# WR-03: regression tests present
grep -n "cgroup_path_rejects_parent_dir_traversal\|cgroup_path_accepts_normal_path\|cgroup_path_rejects_encoded" \
  crates/nono-cli/src/exec_strategy/supervisor_linux.rs
# Expected: 3 lines (one per test function name)

# WR-05: idiomatic errno conversion
grep -c "from_raw_os_error" crates/nono-cli/src/exec_strategy/supervisor_macos.rs
# Expected: 0

# WR-02: no silent setrlimit discard in child branch
grep -c "let _ = setrlimit" crates/nono-cli/src/exec_strategy.rs
# Expected: 0

# WR-04: no PID fallback
grep -c "unwrap_or(child)" crates/nono-cli/src/exec_strategy.rs
# Expected: 0

# Full build + lint + tests
cargo test --package nono-cli cgroup_path_rejects_parent_dir_traversal
cargo test --package nono-cli cgroup_path_accepts_normal_path
cargo test --package nono-cli cgroup_path_rejects_encoded_traversal
cargo build --workspace
cargo clippy --workspace -- -D warnings -D clippy::unwrap_used
cargo fmt --check --all
```
</verification>

<success_criteria>
- `grep -c "starts_with.*sys/fs/cgroup" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` >= 1
- `grep -c "from_raw_os_error" crates/nono-cli/src/exec_strategy/supervisor_macos.rs` == 0
- `grep -c "let _ = setrlimit" crates/nono-cli/src/exec_strategy.rs` == 0
- `grep -c "unwrap_or(child)" crates/nono-cli/src/exec_strategy.rs` == 0
- Three new cgroup_path_* unit tests pass under `cargo test --package nono-cli`
- `cargo build --workspace` exits 0
- `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` exits 0
- `cargo fmt --check --all` exits 0
</success_criteria>

<output>
After completion, create `.planning/phases/25-cross-platform-resl-aipc-unix-design/25-04-RESL-NIX-HARDENING-SUMMARY.md`
</output>
