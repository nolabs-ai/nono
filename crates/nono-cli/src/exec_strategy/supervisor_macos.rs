//! macOS resource-limit application via `setrlimit` + supervisor watchdog.
//!
//! Maps resource-limit flags to macOS enforcement mechanisms:
//!
//! | CLI flag             | Mechanism                  | Notes                        |
//! |----------------------|----------------------------|------------------------------|
//! | `--memory <bytes>`   | `RLIMIT_AS` (address space) | Not RSS — see § RLIMIT_AS vs RSS |
//! | `--max-processes <N>`| `RLIMIT_NPROC`             | Counts against user total    |
//! | `--cpu-percent`      | Rejected at clap parse time | No per-process quota on macOS |
//! | `--timeout <dur>`    | Supervisor `Instant` + `kill(pgrp, SIGKILL)` |        |
//!
//! ## RLIMIT_AS vs RSS
//!
//! `RLIMIT_AS` bounds the process's *virtual address space*, not its resident
//! set size (RSS). A process can pass `--memory 256m` and still consume more
//! than 256 MB of physical memory if its mappings are sparse or shared. This
//! is the documented gap per REQ-RESL-NIX-03; the alternative (RSS-based
//! enforcement via polling) has racy bypass windows and is not portable.
//! RLIMIT_RSS exists on older BSDs but is a no-op on modern macOS.
//!
//! ## CPU percent
//!
//! macOS does not have a per-process CPU-quota equivalent (no cgroup-style
//! `cpu.max`). `RLIMIT_CPU` is CPU-time (not wall-clock) and is intentionally
//! not used because it measures aggregate CPU consumption, not rate.
//! `--cpu-percent` is rejected at clap parse time per REQ-RESL-NIX-03
//! acceptance criterion 3.

use crate::launch_runtime::ResourceLimits;
use nono::{NonoError, Result};

/// macOS resource-limit applier using `setrlimit` in a `pre_exec` hook.
///
/// Created via [`MacosResourceLimits::new`] before the child is spawned.
/// The limits are applied inside the forked child's `pre_exec` hook, before
/// `execve`, so the resource caps are in effect from the first instruction
/// of the sandboxed binary.
pub(crate) struct MacosResourceLimits {
    /// `RLIMIT_AS` soft + hard limit in bytes (from `--memory`). None = no limit.
    memory_bytes: Option<u64>,
    /// `RLIMIT_NPROC` soft + hard limit (from `--max-processes`). None = no limit.
    max_processes: Option<u32>,
    // Note: `timeout` is consumed by the supervisor watchdog (`spawn_macos_timeout_watchdog`),
    // not by the pre_exec hook. It is not stored here.
}

impl MacosResourceLimits {
    /// Create a new `MacosResourceLimits` from the given resource-limit configuration.
    ///
    /// # Defense-in-depth for `cpu_percent`
    ///
    /// `--cpu-percent` is rejected at clap parse time on macOS (see `cli.rs:parse_cpu_percent`).
    /// If it somehow reaches this function (e.g., via a test or FFI caller), this function
    /// returns `Err(NonoError::NotSupportedOnPlatform { feature: "cpu_percent_macos" })`
    /// as a defense-in-depth check.
    ///
    /// # Errors
    ///
    /// Returns `Err(NonoError::NotSupportedOnPlatform { feature: "cpu_percent_macos" })`
    /// if `limits.cpu_percent.is_some()`.
    pub(crate) fn new(limits: &ResourceLimits) -> Result<Self> {
        if limits.cpu_percent.is_some() {
            return Err(NonoError::NotSupportedOnPlatform {
                feature: "cpu_percent_macos".into(),
            });
        }
        Ok(Self {
            memory_bytes: limits.memory_bytes,
            max_processes: limits.max_processes,
        })
    }

    /// Install a `pre_exec` hook on `cmd` that applies `setrlimit` in the forked child.
    ///
    /// The hook runs in the forked child, post-fork pre-exec (before `execve`), so the
    /// limits are in effect from the first instruction of the sandboxed binary.
    ///
    /// # SAFETY
    ///
    /// The closure passed to `pre_exec` runs in the forked child in an async-signal-unsafe
    /// context. The only operations performed inside the closure are:
    ///
    /// - `setrlimit(RLIMIT_AS, ...)` — async-signal-safe per POSIX
    /// - `setrlimit(RLIMIT_NPROC, ...)` — async-signal-safe per POSIX
    ///
    /// No Rust allocator, no Mutex, no `format!` macros are called inside the closure.
    /// All values (`memory_bytes`, `max_processes`) are `Copy` types captured by value.
    ///
    /// The `nix::errno::Errno` → `std::io::Error` conversion uses
    /// `std::io::Error::from` (nix's public `From<Errno> for std::io::Error` impl)
    /// which is also safe in `pre_exec` — internally it constructs an
    /// `io::Error` from the errno's raw integer value, without allocating or
    /// invoking async-signal-unsafe machinery.
    ///
    /// We prefer `From<Errno> for std::io::Error` over the prior `e as i32` cast
    /// because the cast relied on `nix::errno::Errno` being `#[repr(i32)]` —
    /// an internal nix detail. The `From` impl is the documented public API and
    /// is stable across nix's representation changes (WR-05).
    ///
    /// # T-25-01-05 mitigation
    ///
    /// The `memory_bytes` value is checked against `nix::libc::rlim_t::MAX` before the
    /// cast to prevent wrapping on hypothetical 32-bit platforms. nono's MSRV (1.77) and
    /// nix 0.31 both target 64-bit primary; the check is belt-and-suspenders.
    pub(crate) fn install_pre_exec(&self, cmd: &mut std::process::Command) {
        use std::os::unix::process::CommandExt;
        let memory_bytes = self.memory_bytes;
        let max_processes = self.max_processes;

        // SAFETY: pre_exec runs in the forked child, post-fork pre-exec.
        // setrlimit is async-signal-safe (POSIX). No heap allocation or locks
        // are taken inside the closure. All captured values are Copy.
        unsafe {
            cmd.pre_exec(move || -> std::io::Result<()> {
                #[cfg(target_os = "macos")]
                {
                    use nix::sys::resource::{setrlimit, Resource};
                    if let Some(bytes) = memory_bytes {
                        // T-25-01-05: guard against overflow on 32-bit (belt-and-suspenders).
                        let limit = bytes.try_into().unwrap_or(nix::libc::rlim_t::MAX);
                        setrlimit(Resource::RLIMIT_AS, limit, limit)
                            .map_err(std::io::Error::from)?;
                    }
                    if let Some(n) = max_processes {
                        let limit = u64::from(n);
                        setrlimit(Resource::RLIMIT_NPROC, limit, limit)
                            .map_err(std::io::Error::from)?;
                    }
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = (memory_bytes, max_processes);
                }
                Ok(())
            });
        }
    }
}

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

#[cfg(all(test, target_os = "macos"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::launch_runtime::ResourceLimits;

    #[test]
    fn new_rejects_cpu_percent() {
        let limits = ResourceLimits {
            cpu_percent: Some(50),
            memory_bytes: None,
            max_processes: None,
            timeout: None,
        };
        let err = MacosResourceLimits::new(&limits).unwrap_err();
        assert!(
            matches!(
                err,
                NonoError::NotSupportedOnPlatform {
                    ref feature
                } if feature == "cpu_percent_macos"
            ),
            "expected NotSupportedOnPlatform {{ feature: \"cpu_percent_macos\" }}, got: {err:?}"
        );
    }

    #[test]
    fn new_with_all_none_is_ok() {
        let limits = ResourceLimits::default();
        let result = MacosResourceLimits::new(&limits);
        assert!(result.is_ok(), "all-None limits should succeed: {result:?}");
        let r = result.unwrap();
        assert!(r.memory_bytes.is_none());
        assert!(r.max_processes.is_none());
    }
}
