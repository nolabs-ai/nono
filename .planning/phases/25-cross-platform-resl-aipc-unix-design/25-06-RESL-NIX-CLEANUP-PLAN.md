---
phase: 25-cross-platform-resl-aipc-unix-design
plan: 06
type: execute
wave: 2
depends_on: ["25-05"]
files_modified:
  - crates/nono-cli/src/exec_strategy.rs
  - crates/nono-cli/src/exec_strategy/supervisor_linux.rs
  - crates/nono-cli/src/exec_strategy/supervisor_macos.rs
autonomous: true
gap_closure: true
addresses: [WR-C, WR-D]
requirements: [REQ-RESL-NIX-02, REQ-RESL-NIX-03]

must_haves:
  truths:
    - "The watchdog timeout_fired AtomicBool is removed from both Linux and macOS supervisor paths because no consumer reads it; misleading doc comments at exec_strategy.rs:108-109 and supervisor_macos.rs:152-153 are updated to match the actual behavior (watchdog fires SIGKILL / cgroup.kill atomically; inspect-data plumbing is scoped out per CONTEXT.md Q1)"
    - "CgroupSession::disarm method is deleted entirely along with its #[allow(dead_code)] annotation; the armed: bool field is also deleted because once disarm is gone, armed is set only to true at construction and read only by Drop's early-return — both become dead code that violate CLAUDE.md § Lazy use of dead code"
    - "Drop for CgroupSession no longer reads or writes self.armed; it unconditionally performs cgroup-procs scan + directory removal (the previous semantics when armed=true, which was the only actually-used state)"
  artifacts:
    - path: "crates/nono-cli/src/exec_strategy.rs"
      provides: "Removal of timeout_fired AtomicBool declaration (line 833), both .clone() captures (lines 1336, 1355), and the misleading doc comment (lines 108-109); spawn_linux_timeout_watchdog signature simplified"
      contains: "spawn_linux_timeout_watchdog"
    - path: "crates/nono-cli/src/exec_strategy/supervisor_linux.rs"
      provides: "Deletion of disarm method (lines 1047-1052), armed field (line 857), and Drop's early-return on !self.armed (line 1252)"
      contains: "impl Drop for CgroupSession"
    - path: "crates/nono-cli/src/exec_strategy/supervisor_macos.rs"
      provides: "Removal of timeout_fired parameter from spawn_macos_timeout_watchdog (line 170) and its store-and-no-reader call (line 179); doc comment at lines 152-153 updated"
      contains: "spawn_macos_timeout_watchdog"
  key_links:
    - from: "spawn_linux_timeout_watchdog (exec_strategy.rs:114)"
      to: "cgroup.kill write"
      via: "direct std::fs::write — no intermediate AtomicBool flag"
      pattern: "spawn_linux_timeout_watchdog"
    - from: "spawn_macos_timeout_watchdog (supervisor_macos.rs:167)"
      to: "kill(-pgrp, SIGKILL)"
      via: "direct nix::sys::signal::kill — no intermediate AtomicBool flag"
      pattern: "spawn_macos_timeout_watchdog"
    - from: "Drop for CgroupSession"
      to: "fs::remove_dir on cgroup path"
      via: "unconditional cleanup (armed flag removed)"
      pattern: "impl Drop for CgroupSession"
---

<objective>
Close two pre-existing warnings flagged by 25-REVIEW-GAPS.md that the gap-closure scope adopts as in-scope cleanup. Both are CLAUDE.md / project-rule violations or dead-code surfaces that the planner is removing per the lower-blast-radius path documented in 25-VERIFICATION.md `gaps_remaining`.

**WR-C (path b — REMOVE):** The `timeout_fired: Arc<AtomicBool>` flag is stored by `spawn_linux_timeout_watchdog` (exec_strategy.rs:124) and `spawn_macos_timeout_watchdog` (supervisor_macos.rs:179) immediately before delivering SIGKILL / writing `cgroup.kill`, but no consumer ever calls `.load()` on it anywhere in the workspace (verified via project-wide grep). Doc comments at exec_strategy.rs:108-109 and supervisor_macos.rs:152-153 claim the parent's wait loop reads it for `timeout_kill: true` in inspect data — that plumbing does not exist. Per 25-CONTEXT.md Q1, the `memory_kill` / `timeout_kill` inspect-data fields were already scoped as optional follow-up, NOT part of Phase 25 deliverables. The recommendation in <gap_closure_scope> (path b) is to delete the AtomicBool and the misleading doc comments. Path a (wiring it into supervisor footer reporting) would EXPAND scope — explicitly rejected here in favor of CONTEXT.md Q1's already-scoped-out posture.

**WR-D (DELETE):** `CgroupSession::disarm()` at supervisor_linux.rs:1047-1052 carries `#[allow(dead_code)]` which violates CLAUDE.md § "Lazy use of dead code" ("Avoid `#[allow(dead_code)]`. If code is unused, either remove it or write tests that use it."). Workspace-wide grep confirms `disarm` is unreferenced. After deleting `disarm`, the `armed: bool` field is set to `true` only at construction (line 1043) and read only by Drop's early-return at line 1252 — making `armed` a constant `true` for the lifetime of every `CgroupSession`. Both the field and Drop's `if !self.armed { return; }` early-return become dead and are deleted. The remaining Drop body (cgroup-procs scan + directory removal) is preserved verbatim and runs unconditionally — which is the existing behavior when armed is true, the only state ever actually constructed.

Purpose: Close two warnings + remove dead code that the gap-closure code review surfaced. Both fixes have low blast radius (no test changes required beyond what's mechanical for the signature changes) and align with CONTEXT.md scope guidance. No new behavior introduced.

Output: Modified `exec_strategy.rs` (timeout_fired removal + doc comment update + signature change of spawn_linux_timeout_watchdog), `supervisor_linux.rs` (disarm deletion + armed field deletion + Drop simplification), `supervisor_macos.rs` (timeout_fired parameter removal + doc comment update).
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
@.planning/phases/25-cross-platform-resl-aipc-unix-design/25-04-RESL-NIX-HARDENING-SUMMARY.md

<interfaces>
<!-- WR-C surfaces, exec_strategy.rs lines 105-133 (verbatim from source as of branch tip): -->
```rust
/// Spawn a watchdog thread that atomically kills the Linux cgroup at `deadline`.
///
/// Writes `"1\n"` to `<cgroup_path>/cgroup.kill` after sleeping until `deadline`.
/// Sets `timeout_fired` to `true` before writing so the parent's wait loop can
/// record `timeout_kill: true` in inspect data.
///                                                       ^^ WR-C: false claim — no consumer reads timeout_fired
///
/// If the child has already exited (and the cgroup removed by Drop), the write
/// fails silently — this is the normal harmless race.
#[cfg(target_os = "linux")]
pub(crate) fn spawn_linux_timeout_watchdog(
    deadline: std::time::Instant,
    cgroup_path: std::path::PathBuf,
    timeout_fired: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let now = std::time::Instant::now();
        if let Some(remaining) = deadline.checked_duration_since(now) {
            std::thread::sleep(remaining);
        }
        timeout_fired.store(true, std::sync::atomic::Ordering::Release);
        let kill_path = cgroup_path.join("cgroup.kill");
        if let Err(e) = std::fs::write(&kill_path, "1\n") {
            // ENOENT means the cgroup was already removed (child exited before deadline).
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!("cgroup watchdog: failed to write to {kill_path:?}: {e}");
            }
        }
    })
}
```

<!-- WR-C exec_strategy.rs:833 (declaration), 1336 (Linux clone capture), 1355 (macOS clone capture): -->
```rust
// line 832-833:
#[cfg(any(target_os = "linux", target_os = "macos"))]
let timeout_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));

// lines 1331-1342 (Linux watchdog spawn site):
#[cfg(target_os = "linux")]
let _timeout_watchdog = timeout_deadline
    .map(|deadline| {
        if let Some(ref session) = unix_resource_guard {
            let cgroup_path = session.path.clone();
            let fired = timeout_fired.clone();          // <-- to be removed
            Some(spawn_linux_timeout_watchdog(deadline, cgroup_path, fired))
            //                                                      ^^^^^ to be removed
        } else {
            None
        }
    })
    .flatten();

// lines 1343-1371 (macOS watchdog spawn site):
#[cfg(target_os = "macos")]
let _timeout_watchdog = timeout_deadline
    .map(|deadline| {
        use nix::unistd::getpgid;
        // WR-04: Do NOT fall back to child PID on getpgid failure.
        // ... (preserved verbatim) ...
        match getpgid(Some(child)) {
            Ok(child_pgrp) => {
                let fired = timeout_fired.clone();      // <-- to be removed
                Some(supervisor_macos::spawn_macos_timeout_watchdog(
                    deadline, child_pgrp, fired,        // <-- `fired` arg to be removed
                ))
            }
            Err(e) => {
                warn!(
                    "getpgid({}) failed ({}); skipping timeout watchdog — \
                     no PID fallback to avoid wrong-pgrp kill under PID reuse",
                    child.as_raw(),
                    e
                );
                None
            }
        }
    })
    .flatten();
```

<!-- WR-C macOS supervisor surface, supervisor_macos.rs lines 140-187 (verbatim): -->
```rust
/// Spawn a watchdog thread that sends `SIGKILL` to the child process group at `deadline`.
///
/// On macOS, there is no cgroup equivalent for atomic multi-process kill.
/// Instead, this watchdog kills the entire process group (negative PID) via
/// `kill(-pgrp, SIGKILL)`, which delivers SIGKILL to all processes in the group
/// simultaneously. This covers the child and any grandchildren that inherit the
/// same process group.
///
/// # Watchdog behaviour
///
/// 1. Sleeps until `deadline` (using `Instant::checked_duration_since`).
/// 2. Sends `SIGKILL` to the entire process group `child_pgrp`.
/// 3. Sets `timeout_fired` to `true` via `AtomicBool` so the caller can record
///    `timeout_kill: true` in inspect data.
///                                            ^^ WR-C: false claim — no consumer
///
/// # Harmless after child exit
///
/// If the child exits before the deadline, the watchdog fires into an empty
/// process group and the `kill` call returns `ESRCH` (no such process), which
/// the watchdog silently ignores.
///
/// # Returns
///
/// A `JoinHandle` — the caller should `join()` or detach this handle after
/// reaping the child. The watchdog thread is lightweight (sleeping) for the
/// duration of the child's execution.
#[cfg(target_os = "macos")]
pub(crate) fn spawn_macos_timeout_watchdog(
    deadline: std::time::Instant,
    child_pgrp: nix::unistd::Pid,
    timeout_fired: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let now = std::time::Instant::now();
        if let Some(remaining) = deadline.checked_duration_since(now) {
            std::thread::sleep(remaining);
        }
        // Set the flag BEFORE sending SIGKILL so the parent's wait loop sees
        // it even if SIGKILL is delivered instantly.
        timeout_fired.store(true, std::sync::atomic::Ordering::Release);
        // Negative PID = process group. SIGKILL = ungraceful, atomic to the group.
        // Ignore ESRCH (process already exited) — that's the normal race.
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(-child_pgrp.as_raw()),
            nix::sys::signal::Signal::SIGKILL,
        );
    })
}
```

<!-- WR-D surfaces, supervisor_linux.rs (verbatim, line numbers per current branch tip): -->
```rust
// lines 851-858 (struct field):
pub(crate) struct CgroupSession {
    /// Absolute path to the nono-<session-id> cgroup directory.
    pub(crate) path: PathBuf,
    /// Resource limits to apply (stored for `apply_limits`).
    pub(crate) limits: ResourceLimits,
    /// When true, `Drop` removes the cgroup directory.
    armed: bool,                                          // <-- to be deleted
}

// lines 1040-1045 (constructor — armed: true assignment):
Ok(Self {
    path: child_path,
    limits: limits.clone(),
    armed: true,                                          // <-- to be deleted
})

// lines 1047-1052 (the offending method + #[allow(dead_code)]):
/// Disarm the drop cleanup. After calling this, `Drop` will NOT remove the
/// cgroup directory. Use only when cleanup responsibility has been transferred.
#[allow(dead_code)]                                       // <-- CLAUDE.md violation
pub(crate) fn disarm(&mut self) {                         // <-- entire method to be deleted
    self.armed = false;
}

// lines 1250-1276 (Drop impl — armed early-return + assignment to be removed):
impl Drop for CgroupSession {
    fn drop(&mut self) {
        if !self.armed {                                  // <-- early-return to be removed
            return;
        }
        self.armed = false;                               // <-- assignment to be removed (no longer reads)
        // Check for surviving processes (should be empty after cgroup.kill).
        let procs_path = self.path.join("cgroup.procs");
        if let Ok(contents) = std::fs::read_to_string(&procs_path) {
            let surviving = contents.trim();
            if !surviving.is_empty() {
                warn!(
                    "cgroup_v2: Drop: {} still has processes: [{}] — \
                     supervisor bug (cgroup.kill should have cleared them)",
                    self.path.display(),
                    surviving.lines().collect::<Vec<_>>().join(", ")
                );
            }
        }
        // ... rest of drop body unchanged ...
    }
}
```

<!-- Workspace-wide grep confirms disarm is unreferenced (output of `grep -rn "disarm" crates/`):
   crates/nono-cli/src/exec_strategy/supervisor_linux.rs:1051: pub(crate) fn disarm(&mut self) {
   crates/nono-cli/src/exec_strategy/supervisor_linux.rs:1051 (definition only, no callers)
   No other matches in any *.rs file. Safe to delete. -->

<!-- 25-CONTEXT.md Q1 (verbatim, the scope-out posture for inspect-data plumbing):
   "If the field plumbing meaningfully expands plan scope (>2 file additions),
   surface as a deviation during execution rather than expanding upfront."
   ^^ WR-C path (a) wiring would be exactly this kind of expansion.
      Path (b) deletion has zero file-additions impact.
-->
</interfaces>
</context>

<tasks>

<task type="auto" tdd="true">
  <name>Task 1: Remove timeout_fired AtomicBool — declaration, both clone captures, both watchdog signatures, both store calls, both doc comments (WR-C)</name>
  <files>
    crates/nono-cli/src/exec_strategy.rs,
    crates/nono-cli/src/exec_strategy/supervisor_macos.rs
  </files>
  <read_first>
    - crates/nono-cli/src/exec_strategy.rs lines 105-133 (spawn_linux_timeout_watchdog definition + doc)
    - crates/nono-cli/src/exec_strategy.rs lines 825-840 (timeout_fired Arc declaration at line 833)
    - crates/nono-cli/src/exec_strategy.rs lines 1325-1372 (both watchdog spawn call sites)
    - crates/nono-cli/src/exec_strategy/supervisor_macos.rs lines 140-187 (spawn_macos_timeout_watchdog definition + doc)
    - 25-CONTEXT.md § Q1 (inspect-data plumbing scoped out)
    - 25-VERIFICATION.md § "Anti-Patterns" WR-C row (rationale for path b deletion)
  </read_first>
  <behavior>
    - After fix: `grep -n "timeout_fired" crates/nono-cli/src/exec_strategy.rs` returns 0 matches.
    - After fix: `grep -n "timeout_fired" crates/nono-cli/src/exec_strategy/supervisor_macos.rs` returns 0 matches.
    - After fix: `grep -rn "timeout_fired" crates/` returns 0 matches workspace-wide.
    - After fix: `spawn_linux_timeout_watchdog` signature is `pub(crate) fn spawn_linux_timeout_watchdog(deadline: std::time::Instant, cgroup_path: std::path::PathBuf) -> std::thread::JoinHandle<()>` (timeout_fired parameter removed).
    - After fix: `spawn_macos_timeout_watchdog` signature is `pub(crate) fn spawn_macos_timeout_watchdog(deadline: std::time::Instant, child_pgrp: nix::unistd::Pid) -> std::thread::JoinHandle<()>` (timeout_fired parameter removed).
    - After fix: Doc comments at exec_strategy.rs:108-109 and supervisor_macos.rs:152-153 no longer claim "Sets `timeout_fired` to `true`" / "the parent's wait loop can record `timeout_kill: true` in inspect data".
    - After fix: All existing tests in `crates/nono-cli/tests/resl_nix_async_signal_safety.rs` (5 tests) continue to pass.
    - After fix: `cargo build --workspace` succeeds; `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` exits 0.
  </behavior>
  <action>
    Apply six independent edits across two files. All are mechanical removals.

    ---

    **EDIT 1 — exec_strategy.rs lines 105-133 (spawn_linux_timeout_watchdog):**

    Replace the existing function (currently lines 105-133, including its doc block) with:

    ```rust
    /// Spawn a watchdog thread that atomically kills the Linux cgroup at `deadline`.
    ///
    /// Writes `"1\n"` to `<cgroup_path>/cgroup.kill` after sleeping until `deadline`.
    /// `cgroup.kill` is the cgroup v2 atomic-multi-process-kill primitive — writing
    /// "1" delivers SIGKILL to every PID in the cgroup tree atomically.
    ///
    /// If the child has already exited (and the cgroup removed by Drop), the write
    /// fails with ENOENT — this is the normal harmless race and is silently ignored.
    /// Other write failures emit a warning.
    #[cfg(target_os = "linux")]
    pub(crate) fn spawn_linux_timeout_watchdog(
        deadline: std::time::Instant,
        cgroup_path: std::path::PathBuf,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let now = std::time::Instant::now();
            if let Some(remaining) = deadline.checked_duration_since(now) {
                std::thread::sleep(remaining);
            }
            let kill_path = cgroup_path.join("cgroup.kill");
            if let Err(e) = std::fs::write(&kill_path, "1\n") {
                // ENOENT means the cgroup was already removed (child exited before deadline).
                if e.kind() != std::io::ErrorKind::NotFound {
                    warn!("cgroup watchdog: failed to write to {kill_path:?}: {e}");
                }
            }
        })
    }
    ```

    Two surfaces removed: (a) `timeout_fired: std::sync::Arc<std::sync::atomic::AtomicBool>` parameter, (b) `timeout_fired.store(true, ...)` call. Doc comment line `Sets timeout_fired to true before writing so the parent's wait loop can record timeout_kill: true in inspect data.` is removed (replaced with the cgroup.kill primitive description above).

    ---

    **EDIT 2 — exec_strategy.rs line 833 area (timeout_fired Arc declaration):**

    Locate the declaration (currently line 832-833):
    ```rust
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let timeout_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    ```

    Delete BOTH lines (the `#[cfg]` attribute and the `let timeout_fired = ...;` statement). After deletion, the surrounding code looks like:
    ```rust
        // Pre-compute the deadline for the timeout watchdog (spawned after fork).
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let timeout_deadline = resource_limits
            .timeout
            .map(|d| std::time::Instant::now() + d);

        // Clear any stale forwarding target before forking.
        clear_signal_forwarding_target();
    ```
    (i.e. the `let timeout_fired = ...;` line and its `#[cfg]` are simply removed, leaving the existing `timeout_deadline` block and the `clear_signal_forwarding_target()` call adjacent.)

    ---

    **EDIT 3 — exec_strategy.rs lines 1331-1342 (Linux watchdog spawn site):**

    Locate the Linux spawn block (currently around lines 1331-1342):
    ```rust
                #[cfg(target_os = "linux")]
                let _timeout_watchdog = timeout_deadline
                    .map(|deadline| {
                        if let Some(ref session) = unix_resource_guard {
                            let cgroup_path = session.path.clone();
                            let fired = timeout_fired.clone();
                            Some(spawn_linux_timeout_watchdog(deadline, cgroup_path, fired))
                        } else {
                            None
                        }
                    })
                    .flatten();
    ```

    Replace with:
    ```rust
                #[cfg(target_os = "linux")]
                let _timeout_watchdog = timeout_deadline
                    .map(|deadline| {
                        if let Some(ref session) = unix_resource_guard {
                            let cgroup_path = session.path.clone();
                            Some(spawn_linux_timeout_watchdog(deadline, cgroup_path))
                        } else {
                            None
                        }
                    })
                    .flatten();
    ```

    Two surfaces removed: `let fired = timeout_fired.clone();` line, and the `, fired` argument from the spawn call.

    ---

    **EDIT 4 — exec_strategy.rs lines 1343-1371 (macOS watchdog spawn site):**

    Locate the macOS spawn block (currently around lines 1343-1371):
    ```rust
                #[cfg(target_os = "macos")]
                let _timeout_watchdog = timeout_deadline
                    .map(|deadline| {
                        use nix::unistd::getpgid;
                        // WR-04: Do NOT fall back to child PID on getpgid failure.
                        // ... (long comment block preserved verbatim) ...
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
                                     no PID fallback to avoid wrong-pgrp kill under PID reuse",
                                    child.as_raw(),
                                    e
                                );
                                None
                            }
                        }
                    })
                    .flatten();
    ```

    Apply two surgical changes ONLY:
    - Delete the line `let fired = timeout_fired.clone();` (currently around line 1355).
    - In the `spawn_macos_timeout_watchdog(deadline, child_pgrp, fired,)` call, remove the trailing `, fired` argument so it reads `spawn_macos_timeout_watchdog(deadline, child_pgrp,)` (the trailing comma after `child_pgrp` is fine; rustfmt will normalize it to `spawn_macos_timeout_watchdog(deadline, child_pgrp)`).

    ALL OTHER CONTENTS of this match arm — including the entire WR-04 doc comment block, the `Err(e) => { warn!(...) }` arm, etc. — MUST be preserved verbatim. Verify by re-reading lines around 1346-1370 after the edit and confirming the WR-04 comment text is unchanged.

    ---

    **EDIT 5 — supervisor_macos.rs lines 140-187 (spawn_macos_timeout_watchdog):**

    Replace the existing function (currently lines 140-187, including doc block) with:

    ```rust
    /// Spawn a watchdog thread that sends `SIGKILL` to the child process group at `deadline`.
    ///
    /// On macOS, there is no cgroup equivalent for atomic multi-process kill.
    /// Instead, this watchdog kills the entire process group (negative PID) via
    /// `kill(-pgrp, SIGKILL)`, which delivers SIGKILL to all processes in the group
    /// simultaneously. This covers the child and any grandchildren that inherit the
    /// same process group.
    ///
    /// # Watchdog behaviour
    ///
    /// 1. Sleeps until `deadline` (using `Instant::checked_duration_since`).
    /// 2. Sends `SIGKILL` to the entire process group `child_pgrp` via `kill(-pgrp, SIGKILL)`.
    ///
    /// # Harmless after child exit
    ///
    /// If the child exits before the deadline, the watchdog fires into an empty
    /// process group and the `kill` call returns `ESRCH` (no such process), which
    /// the watchdog silently ignores.
    ///
    /// # Returns
    ///
    /// A `JoinHandle` — the caller should `join()` or detach this handle after
    /// reaping the child. The watchdog thread is lightweight (sleeping) for the
    /// duration of the child's execution.
    #[cfg(target_os = "macos")]
    pub(crate) fn spawn_macos_timeout_watchdog(
        deadline: std::time::Instant,
        child_pgrp: nix::unistd::Pid,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let now = std::time::Instant::now();
            if let Some(remaining) = deadline.checked_duration_since(now) {
                std::thread::sleep(remaining);
            }
            // Negative PID = process group. SIGKILL = ungraceful, atomic to the group.
            // Ignore ESRCH (process already exited) — that's the normal race.
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(-child_pgrp.as_raw()),
                nix::sys::signal::Signal::SIGKILL,
            );
        })
    }
    ```

    Three surfaces removed:
    - Doc list item `3. Sets timeout_fired to true via AtomicBool so the caller can record timeout_kill: true in inspect data.`
    - `timeout_fired: std::sync::Arc<std::sync::atomic::AtomicBool>` parameter.
    - `timeout_fired.store(true, std::sync::atomic::Ordering::Release);` call and its `// Set the flag BEFORE sending SIGKILL...` comment.

    ---

    **EDIT 6 — sanity check: search for any remaining timeout_fired or timeout_kill references that need updating:**

    After applying EDITs 1-5, run:
    ```bash
    grep -rn "timeout_fired" crates/
    grep -rn "timeout_kill" crates/
    ```

    Expected: ZERO matches for `timeout_fired` workspace-wide. `timeout_kill` may still match in REQUIREMENTS.md or other planning docs (those are not in `crates/`); within `crates/` it should also be zero unless there is a comment elsewhere — if any match exists, surface as a deviation rather than editing autonomously.
  </action>
  <verify>
    <automated>
      grep -c "timeout_fired" crates/nono-cli/src/exec_strategy.rs
      grep -c "timeout_fired" crates/nono-cli/src/exec_strategy/supervisor_macos.rs
      grep -rn "timeout_fired" crates/ 2>&1
      grep -n "spawn_linux_timeout_watchdog" crates/nono-cli/src/exec_strategy.rs
      grep -n "spawn_macos_timeout_watchdog" crates/nono-cli/src/exec_strategy/supervisor_macos.rs
      grep -n "fn spawn_linux_timeout_watchdog" crates/nono-cli/src/exec_strategy.rs
      grep -n "fn spawn_macos_timeout_watchdog" crates/nono-cli/src/exec_strategy/supervisor_macos.rs
      grep -n "match getpgid(" crates/nono-cli/src/exec_strategy.rs
      cargo build --workspace 2>&1 | tail -15
      cargo test --package nono-cli --test resl_nix_async_signal_safety 2>&1 | tail -15
      cargo clippy --workspace -- -D warnings -D clippy::unwrap_used 2>&1 | tail -10
      cargo fmt --check --all 2>&1 | tail -10
    </automated>
  </verify>
  <acceptance_criteria>
    1. `grep -c "timeout_fired" crates/nono-cli/src/exec_strategy.rs` returns 0.
    2. `grep -c "timeout_fired" crates/nono-cli/src/exec_strategy/supervisor_macos.rs` returns 0.
    3. `grep -rn "timeout_fired" crates/` returns 0 matches workspace-wide (output is empty).
    4. The signature of `spawn_linux_timeout_watchdog` exactly matches `pub(crate) fn spawn_linux_timeout_watchdog(\n    deadline: std::time::Instant,\n    cgroup_path: std::path::PathBuf,\n) -> std::thread::JoinHandle<()>` (verifiable: `grep -A 3 "fn spawn_linux_timeout_watchdog" exec_strategy.rs` shows two parameters, not three).
    5. The signature of `spawn_macos_timeout_watchdog` exactly matches `pub(crate) fn spawn_macos_timeout_watchdog(\n    deadline: std::time::Instant,\n    child_pgrp: nix::unistd::Pid,\n) -> std::thread::JoinHandle<()>` (verifiable: `grep -A 3 "fn spawn_macos_timeout_watchdog" supervisor_macos.rs` shows two parameters, not three).
    6. `grep -n "match getpgid(" crates/nono-cli/src/exec_strategy.rs` returns exactly 1 match (proving the WR-04 fix structure was preserved verbatim through this edit).
    7. `cargo build --workspace` exits 0.
    8. `cargo test --package nono-cli --test resl_nix_async_signal_safety` exits 0 with all 5 tests passing (these tests do not reference `timeout_fired`, so they should be unaffected).
    9. `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` exits 0.
    10. `cargo fmt --check --all` exits 0.
    11. **D-19/D-21 invariant:** `git diff --stat HEAD~1 HEAD -- crates/nono-cli/src/exec_strategy_windows/ crates/nono/src/sandbox/windows.rs` is empty after this task's commit.
  </acceptance_criteria>
  <done>timeout_fired AtomicBool removed end-to-end: declaration deleted, both clone captures deleted, both watchdog function signatures simplified to two parameters, both store calls deleted, both misleading doc comments updated to describe actual behavior. Workspace builds, all existing tests pass, clippy + fmt clean. WR-04 match getpgid arm preserved verbatim.</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Delete CgroupSession::disarm method, armed field, and Drop's armed early-return (WR-D)</name>
  <files>crates/nono-cli/src/exec_strategy/supervisor_linux.rs</files>
  <read_first>
    - crates/nono-cli/src/exec_strategy/supervisor_linux.rs lines 850-860 (struct definition with `armed: bool` field at line 857)
    - crates/nono-cli/src/exec_strategy/supervisor_linux.rs lines 1037-1052 (constructor `Ok(Self { ... armed: true, })` and `disarm` method)
    - crates/nono-cli/src/exec_strategy/supervisor_linux.rs lines 1248-1276 (Drop impl with `if !self.armed { return; }` early-return at 1252 and `self.armed = false;` at 1255)
    - CLAUDE.md § "Lazy use of dead code" (rule being applied)
    - 25-REVIEW-GAPS.md WR-D section
  </read_first>
  <behavior>
    - After fix: `grep -n "armed" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` returns 0 matches.
    - After fix: `grep -n "disarm" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` returns 0 matches.
    - After fix: `grep -rn "disarm" crates/` returns 0 matches workspace-wide (was already only defined in this one file).
    - After fix: `grep -c "#\[allow(dead_code)\]" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` returns 0 (or stays the same as before this task — this task should not introduce ANY new `#[allow(dead_code)]`).
    - After fix: Drop for CgroupSession unconditionally runs the procs-scan + remove_dir cleanup (no `if !self.armed { return; }`, no `self.armed = false;`).
    - After fix: All existing tests in `cargo test --package nono-cli` continue to pass.
    - After fix: `cargo build --workspace` succeeds; `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` exits 0.
  </behavior>
  <action>
    Apply four mechanical deletions in `crates/nono-cli/src/exec_strategy/supervisor_linux.rs`. All four shrink the surface; none add new code.

    ---

    **DELETION 1 — Remove `armed: bool` field from CgroupSession struct (around line 857):**

    Locate the struct definition (currently lines 851-858):
    ```rust
        pub(crate) struct CgroupSession {
            /// Absolute path to the nono-<session-id> cgroup directory.
            pub(crate) path: PathBuf,
            /// Resource limits to apply (stored for `apply_limits`).
            pub(crate) limits: ResourceLimits,
            /// When true, `Drop` removes the cgroup directory.
            armed: bool,
        }
    ```

    Delete the two lines:
    ```rust
            /// When true, `Drop` removes the cgroup directory.
            armed: bool,
    ```

    Resulting struct:
    ```rust
        pub(crate) struct CgroupSession {
            /// Absolute path to the nono-<session-id> cgroup directory.
            pub(crate) path: PathBuf,
            /// Resource limits to apply (stored for `apply_limits`).
            pub(crate) limits: ResourceLimits,
        }
    ```

    ---

    **DELETION 2 — Remove `armed: true` initializer in constructor (around line 1043):**

    Locate the constructor's `Ok(Self { ... })` (currently lines 1040-1045):
    ```rust
                Ok(Self {
                    path: child_path,
                    limits: limits.clone(),
                    armed: true,
                })
    ```

    Delete the line `armed: true,`. Resulting:
    ```rust
                Ok(Self {
                    path: child_path,
                    limits: limits.clone(),
                })
    ```

    Note the doc comment a few lines above (currently around line 987) reads `4. Stores the path, limits, and armed flag for later use.` — update it to `4. Stores the path and limits for later use.` (drop "and armed flag"). If a different doc comment shape is in the actual source, replace `armed flag` references with the corresponding text (do not invent new prose).

    ---

    **DELETION 3 — Remove the `disarm` method entirely (lines 1047-1052):**

    Locate the method:
    ```rust
            /// Disarm the drop cleanup. After calling this, `Drop` will NOT remove the
            /// cgroup directory. Use only when cleanup responsibility has been transferred.
            #[allow(dead_code)]
            pub(crate) fn disarm(&mut self) {
                self.armed = false;
            }
    ```

    Delete ALL six lines (the doc comment, the `#[allow(dead_code)]` attribute, the `pub(crate) fn disarm(&mut self) {`, the `self.armed = false;`, and the closing `}`).

    The line BEFORE the deleted block currently ends the constructor's closing `}` followed by a blank line. The line AFTER currently begins another method or impl block. Verify continuity by reading the surrounding lines after deletion.

    ---

    **DELETION 4 — Simplify Drop impl to remove armed-related logic (lines 1250-1256):**

    Locate the Drop impl opening (currently lines 1250-1256):
    ```rust
        impl Drop for CgroupSession {
            fn drop(&mut self) {
                if !self.armed {
                    return;
                }
                self.armed = false;
                // Check for surviving processes (should be empty after cgroup.kill).
    ```

    Delete the four lines:
    ```rust
                if !self.armed {
                    return;
                }
                self.armed = false;
    ```

    Resulting:
    ```rust
        impl Drop for CgroupSession {
            fn drop(&mut self) {
                // Check for surviving processes (should be empty after cgroup.kill).
    ```

    ALL OTHER content of the Drop impl (procs_path read, surviving warning, remove_dir call, etc.) MUST be preserved verbatim — only the four lines above are deleted.

    ---

    **VERIFICATION reasoning** (NOT a code edit):

    After these four deletions, `armed` and `disarm` are gone from `crates/nono-cli/src/exec_strategy/supervisor_linux.rs`. The constructor returns a `CgroupSession` with no `armed` field; `Drop` runs the cleanup unconditionally (which was the only effective behavior since `armed` was never set to `false` outside `disarm` — and `disarm` was never called). Behavior is preserved exactly. No callers of `disarm` exist anywhere (verified via workspace grep), so no other files need editing.

    The `pub(crate) struct CgroupSession` continues to expose `path: PathBuf` and `limits: ResourceLimits` — these are used by other functions (e.g. `apply_limits`, the watchdog spawn site at exec_strategy.rs:1335 reads `session.path.clone()`). DO NOT touch those callers — they only read public fields and are unaffected by this task's edits.
  </action>
  <verify>
    <automated>
      grep -c "\barmed\b" crates/nono-cli/src/exec_strategy/supervisor_linux.rs
      grep -c "disarm" crates/nono-cli/src/exec_strategy/supervisor_linux.rs
      grep -rn "disarm" crates/
      grep -c "#\[allow(dead_code)\]" crates/nono-cli/src/exec_strategy/supervisor_linux.rs
      grep -n "impl Drop for CgroupSession" crates/nono-cli/src/exec_strategy/supervisor_linux.rs
      grep -A 5 "impl Drop for CgroupSession" crates/nono-cli/src/exec_strategy/supervisor_linux.rs
      cargo build --workspace 2>&1 | tail -15
      cargo test --package nono-cli 2>&1 | tail -15
      cargo clippy --workspace -- -D warnings -D clippy::unwrap_used 2>&1 | tail -10
      cargo fmt --check --all 2>&1 | tail -10
    </automated>
  </verify>
  <acceptance_criteria>
    1. `grep -c "\barmed\b" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` returns 0 (the word `armed` as a whole-word match is gone).
    2. `grep -c "disarm" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` returns 0.
    3. `grep -rn "disarm" crates/` returns 0 matches workspace-wide.
    4. `grep -c "#\[allow(dead_code)\]" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` returns the SAME count as before this task (0 if no other allow(dead_code) annotations exist; do not introduce any new ones).
    5. `grep -A 5 "impl Drop for CgroupSession" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` shows the Drop body starting with `// Check for surviving processes` (or equivalent comment), NOT with `if !self.armed`.
    6. `cargo build --workspace` exits 0.
    7. `cargo test --package nono-cli` exits 0 (all existing tests pass — `armed` and `disarm` had no test coverage, so removing them does not break any test).
    8. `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` exits 0.
    9. `cargo fmt --check --all` exits 0.
    10. **D-19/D-21 invariant:** `git diff --stat HEAD~1 HEAD -- crates/nono-cli/src/exec_strategy_windows/ crates/nono/src/sandbox/windows.rs` is empty after this task's commit.
  </acceptance_criteria>
  <done>CgroupSession::disarm method deleted (including its #[allow(dead_code)] attribute and 4-line doc comment); armed field deleted from struct + constructor; Drop impl simplified to unconditionally run cleanup. Workspace builds, all tests pass, clippy + fmt clean. CLAUDE.md § Lazy use of dead code rule satisfied.</done>
</task>

</tasks>

<threat_model>
## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| Watchdog thread → caller (post-wait reporting) | `timeout_fired` claimed to communicate "did the watchdog fire?" but no consumer existed. False signal in doc comments. |
| Drop semantics for cgroup cleanup | `armed` field claimed to gate cleanup, but `disarm` was never called — cleanup always ran. False optionality. |
| Project-rule enforcement | `#[allow(dead_code)]` on `disarm` violates CLAUDE.md, weakening the convention that dead code must be removed or covered. |

## STRIDE Threat Register

| Threat ID | Category | Component | Disposition | Mitigation Plan |
|-----------|----------|-----------|-------------|-----------------|
| T-25-06-01 | Information Disclosure (misleading docs) | exec_strategy.rs:108-109 and supervisor_macos.rs:152-153 doc comments claiming `timeout_fired` is read for inspect data | mitigate | Task 1: Delete the AtomicBool entirely (path b in 25-VERIFICATION.md) and update doc comments to accurately describe the watchdog's actual behavior (atomic kill via cgroup.kill / SIGKILL to pgrp). No new behavior introduced; only false claims removed. Inspect-data plumbing remains explicitly out of scope per CONTEXT.md Q1. |
| T-25-06-02 | Tampering (false optionality) | CgroupSession::armed field + disarm method suggesting Drop cleanup was conditional, when in practice it was always unconditional | mitigate | Task 2: Delete the field, the method, the constructor initializer, and the Drop early-return. Behavior is preserved (cleanup runs unconditionally, which was the only state ever constructed). |
| T-25-06-03 | Repudiation (rule-bypass via #[allow(dead_code)]) | supervisor_linux.rs:1049 `#[allow(dead_code)]` on disarm violating CLAUDE.md convention | mitigate | Task 2: Remove the annotation along with the dead method; keeps the project's anti-dead-code discipline intact. |
| T-25-06-04 | Defense-in-depth bypass | Future maintainer adds another `#[allow(dead_code)]` to silence a similar warning | accept | Out of scope this cycle. CLAUDE.md is the controlling rule and is unchanged; the next reviewer will catch new instances under the same rule. No new mitigation primitive needed in code. |
</threat_model>

<verification>
After both tasks:

```bash
# WR-C: timeout_fired removed end-to-end
grep -rn "timeout_fired" crates/
# Expected: ZERO matches

# WR-C: spawn_linux_timeout_watchdog signature simplified
grep -A 3 "fn spawn_linux_timeout_watchdog" crates/nono-cli/src/exec_strategy.rs
# Expected: signature shows two parameters (deadline + cgroup_path), not three

# WR-C: spawn_macos_timeout_watchdog signature simplified
grep -A 3 "fn spawn_macos_timeout_watchdog" crates/nono-cli/src/exec_strategy/supervisor_macos.rs
# Expected: signature shows two parameters (deadline + child_pgrp), not three

# WR-C: WR-04 match getpgid arm preserved verbatim
grep -n "match getpgid(" crates/nono-cli/src/exec_strategy.rs
# Expected: exactly 1 match (the WR-04 fix is intact)

# WR-D: armed field gone
grep -c "\\barmed\\b" crates/nono-cli/src/exec_strategy/supervisor_linux.rs
# Expected: 0

# WR-D: disarm method gone
grep -c "disarm" crates/nono-cli/src/exec_strategy/supervisor_linux.rs
# Expected: 0
grep -rn "disarm" crates/
# Expected: 0 matches workspace-wide

# WR-D: no new #[allow(dead_code)]
grep -c "#\[allow(dead_code)\]" crates/nono-cli/src/exec_strategy/supervisor_linux.rs
# Expected: 0 (or unchanged from baseline; do not introduce new ones)

# WR-D: Drop simplified
grep -A 5 "impl Drop for CgroupSession" crates/nono-cli/src/exec_strategy/supervisor_linux.rs
# Expected: body starts with `fn drop(&mut self) {` followed by `// Check for surviving processes` comment (not `if !self.armed`)

# Full build + lint + tests + fmt
cargo build --workspace
cargo test --package nono-cli
cargo clippy --workspace -- -D warnings -D clippy::unwrap_used
cargo fmt --check --all

# D-19 / D-21 byte-identical Windows preservation invariant
git diff --stat HEAD~2 HEAD -- crates/nono-cli/src/exec_strategy_windows/ crates/nono/src/sandbox/windows.rs
# Expected: empty (this plan touches only Linux/macOS source)
```
</verification>

<success_criteria>
- `grep -rn "timeout_fired" crates/` returns 0 matches workspace-wide.
- `spawn_linux_timeout_watchdog` signature: `(deadline: std::time::Instant, cgroup_path: std::path::PathBuf) -> std::thread::JoinHandle<()>` (two parameters).
- `spawn_macos_timeout_watchdog` signature: `(deadline: std::time::Instant, child_pgrp: nix::unistd::Pid) -> std::thread::JoinHandle<()>` (two parameters).
- WR-04 `match getpgid(...)` arm in exec_strategy.rs is byte-identical to its pre-task-1 contents (other than the `, fired` argument removal in the Ok arm).
- `grep -c "armed" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` returns 0.
- `grep -c "disarm" crates/nono-cli/src/exec_strategy/supervisor_linux.rs` returns 0.
- `grep -rn "disarm" crates/` returns 0 matches workspace-wide.
- No new `#[allow(dead_code)]` annotations introduced anywhere in `crates/`.
- Drop for CgroupSession runs unconditionally (no `if !self.armed { return; }` early-return).
- `cargo build --workspace` exits 0.
- `cargo test --package nono-cli` exits 0.
- `cargo clippy --workspace -- -D warnings -D clippy::unwrap_used` exits 0.
- `cargo fmt --check --all` exits 0.
- D-19 / D-21 invariant: `git diff --stat HEAD~N HEAD -- crates/nono-cli/src/exec_strategy_windows/ crates/nono/src/sandbox/windows.rs` is empty across this plan's commits.
</success_criteria>

<output>
After completion, create `.planning/phases/25-cross-platform-resl-aipc-unix-design/25-06-RESL-NIX-CLEANUP-SUMMARY.md`
</output>
