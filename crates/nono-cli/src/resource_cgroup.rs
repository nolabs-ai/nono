//! Linux cgroup v2 resource enforcement (issue #1102).
//!
//! # What this does, in plain terms
//!
//! When a sandboxed run is given a `--memory` (or `--max-procs`) limit, this
//! module puts the program in a kernel-enforced "box" so it cannot use more than
//! that. If it tries, the Linux kernel kills it instantly — and *only* it — so a
//! runaway agent cannot drag down the rest of the machine. Think of a room with
//! a strict capacity sign: step over the line and the door slams, on that room
//! alone.
//!
//! The mechanism is **cgroup v2** ("control groups"), the same kernel feature
//! containers use. A cgroup is just a directory under `/sys/fs/cgroup`: you set
//! limits by writing numbers into files inside it (its "knobs"), and you put a
//! process in it by writing the process id into its `cgroup.procs` file. We
//! create one such directory per run (a "leaf"), set the knobs, the child moves
//! *itself* in, and we delete the directory when the run ends.
//!
//! # Who runs this
//!
//! The unsandboxed *supervisor* (nono's parent process) builds the box and arms
//! it before forking. The sandboxed *child* then puts itself in the box — see
//! the race note below for why the child, not the parent, does the attach.
//!
//! # Containing the whole process tree (the race, and why self-attach)
//!
//! A cgroup caps *every* process inside it together, and a forked child inherits
//! its parent's cgroup automatically — so once a process is in the leaf, its
//! whole subtree is capped and dies atomically. The only hard part is getting
//! the first process *into* the leaf without leaving a gap.
//!
//! If the **parent** moved the child in *after* `fork()`, there would be a brief
//! window in which the child is already running but not yet boxed; a child that
//! forks its own children inside that window could slip a few of them out into
//! the parent's (unconstrained) cgroup. To close that window, the **child
//! attaches itself**: the parent opens the leaf's `cgroup.procs` write fd before
//! forking (so the child inherits it), and the child writes its own pid through
//! that fd before it does anything else — before it can fork or exec. It is
//! therefore in the box by construction, with no escape window, regardless of
//! timing (see [`child_self_attach`]).
//!
//! # Fail-closed (AGENTS.md "Fail Secure")
//!
//! If the box cannot be built, armed, or entered, the run is refused rather than
//! allowed to proceed unprotected:
//! - Creating the box and setting its knobs happen *before* the child is forked,
//!   so any failure is a [`NonoError`] returned while nothing is running yet.
//! - If the child cannot self-attach after fork, it kills itself
//!   (`_exit(126)`) before applying the sandbox or exec'ing — it never runs the
//!   thing the limit was meant to constrain.
//!
//! # The knobs we set
//!
//! Mirrors the by-hand proof at `~/alwaysfurther/cgroup-spike/` (the fixture this
//! is graded against):
//! - `memory.max`         — the hard memory ceiling; cross it and the kernel OOM-kills.
//! - `memory.swap.max=0`  — forbid spilling to swap, which would let it dodge the ceiling.
//! - `memory.oom.group=1` — on OOM, kill the *whole* box at once, not one random member.
//! - `cpu.max`            — cap CPU *bandwidth* (a share of the cores) so a
//!   runaway can spin forever but never starve the host; a rate limit, not a
//!   cumulative CPU-seconds budget.
//! - `pids.max`           — cap the number of processes (stops a fork bomb).
//!
//! We deliberately do **not** set `memory.high` (a softer "ease off" threshold):
//! with swap forbidden, a runaway allocator has nothing to reclaim, so it would
//! stall for many seconds before finally being killed — defeating the point of a
//! fast, clean kill. (Design open question #2: revisit as an opt-in for genuine
//! near-limit workloads if there is data showing it helps.)
//!
//! Choosing *which* backend to enforce with (the WSL2 / non-systemd probe and
//! the `auto`/`cgroup`/`portable` resolution) is a later step; this targets the
//! common case — a normal desktop/server login, i.e. a systemd `Delegate=yes`
//! user session.

use nix::libc;
use nono::{NonoError, ResourceLimits, Result};
use std::fs::{self, File, OpenOptions};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

/// One sandboxed run's resource "box": a cgroup v2 directory we create, arm with
/// limits, the child moves into, and we delete when the run ends.
///
/// Created pre-fork by [`CgroupLeaf::create`]; the child attaches itself through
/// the inherited `cgroup.procs` fd ([`CgroupLeaf::procs_raw_fd`] +
/// [`child_self_attach`]). On drop the box is emptied (any survivors killed) and
/// the directory removed, so an early return or panic cannot leak a cgroup.
pub struct CgroupLeaf {
    /// Absolute path of the leaf directory, e.g.
    /// `/sys/fs/cgroup/.../user@1000.service/nono.<pid>`.
    path: PathBuf,
    /// Write handle to the leaf's `cgroup.procs`, opened pre-fork so the child
    /// inherits it across `fork` and can self-attach before it execs. The
    /// parent never writes through it; it exists only to be inherited. Closed
    /// when the leaf is dropped (and in the child at `execve`, via O_CLOEXEC).
    procs: File,
}

impl CgroupLeaf {
    /// Create the leaf, write the requested knobs, and open its `cgroup.procs`
    /// for the child to self-attach through. Pre-fork; fail-closed.
    ///
    /// # Errors
    /// Returns [`NonoError::SandboxInit`] if the session has no delegated
    /// cgroup v2 subtree, the required controllers are not delegated, or any
    /// knob write / `cgroup.procs` open fails. On any failure no partial leaf is
    /// left behind.
    pub fn create(limits: &ResourceLimits) -> Result<Self> {
        let base = delegated_base()?;
        ensure_controllers_delegated(&base, limits)?;

        let path = base.join(format!("nono.{}", std::process::id()));
        // A leftover leaf with our exact pid is unexpected (pid reuse after a
        // crash). Reusing it could inherit stale members, so treat an existing
        // directory as a hard error rather than silently adopting it.
        fs::create_dir(&path).map_err(|e| {
            NonoError::SandboxInit(format!(
                "resource: failed to create cgroup leaf {}: {e}",
                path.display()
            ))
        })?;

        // The leaf directory now exists; from here any failure must remove it.
        // `arm` does the remaining fallible work; on error we tear the directory
        // down before returning (no `Self` is constructed yet, so there is no
        // double teardown).
        match Self::arm(path.clone(), limits) {
            Ok(leaf) => Ok(leaf),
            Err(e) => {
                teardown(&path);
                Err(e)
            }
        }
    }

    /// Write the knobs and open `cgroup.procs`, building the owned [`CgroupLeaf`].
    /// Separated from [`create`](Self::create) so a failure here is cleaned up by
    /// the caller's `teardown` of the already-created directory.
    fn arm(path: PathBuf, limits: &ResourceLimits) -> Result<Self> {
        write_knobs(&path, limits)?;
        let procs_path = path.join("cgroup.procs");
        // O_CLOEXEC (Rust's default) is intentional: the fd is inherited across
        // `fork` so the child can self-attach, then closes automatically at the
        // child's `execve`.
        let procs = OpenOptions::new()
            .write(true)
            .open(&procs_path)
            .map_err(|e| {
                NonoError::SandboxInit(format!(
                    "resource: failed to open {} for self-attach ({e})",
                    procs_path.display()
                ))
            })?;
        Ok(Self { path, procs })
    }

    /// Raw fd of the leaf's `cgroup.procs`, to be inherited by the forked child
    /// and written through by [`child_self_attach`]. Valid for the lifetime of
    /// this `CgroupLeaf`.
    #[must_use]
    pub fn procs_raw_fd(&self) -> RawFd {
        self.procs.as_raw_fd()
    }
}

impl Drop for CgroupLeaf {
    fn drop(&mut self) {
        teardown(&self.path);
    }
}

/// The child puts **itself** into the resource cgroup by writing its own pid to
/// the inherited `cgroup.procs` write fd, in the post-fork window *before* it
/// applies the sandbox or execs. Because it runs before the child can fork or
/// exec, every descendant it later spawns is inside the cgroup by construction —
/// there is no window for a process to escape into the parent's cgroup.
///
/// Async-signal-safe: it only calls `getpid`, formats the pid into a stack
/// buffer, and `write`s — no allocation and no locks — so it is safe to call in
/// the post-fork child path. Returns `true` on a complete write; on `false` the
/// caller must `_exit` the child (fail-closed: never run unconfined).
///
/// # Safety
/// `procs_fd` must be a valid, writable fd for the leaf's `cgroup.procs`,
/// inherited from the parent across `fork`.
#[must_use = "on `false` the child is unconfined and the caller MUST _exit it (fail-closed)"]
pub fn child_self_attach(procs_fd: RawFd) -> bool {
    // SAFETY: `getpid` is async-signal-safe and always succeeds; in the child it
    // returns the child's own pid.
    let pid = unsafe { libc::getpid() };
    let mut buf = [0u8; MAX_PID_DIGITS];
    let encoded = format_pid_decimal(pid, &mut buf);
    // SAFETY: writing `encoded.len()` bytes from a stack buffer to a raw fd is
    // async-signal-safe. A short or failed write is treated as failure so the
    // caller fails closed.
    let written = unsafe {
        libc::write(
            procs_fd,
            encoded.as_ptr().cast::<libc::c_void>(),
            encoded.len(),
        )
    };
    written == encoded.len() as isize
}

/// `i32::MAX` is `2147483647` (10 digits); pids are positive, so 10 digits is the
/// widest decimal a pid can require.
const MAX_PID_DIGITS: usize = 10;

/// Format `pid` as decimal ASCII into `buf` without allocating (async-signal-safe),
/// returning the populated trailing slice. A non-positive `pid` is defensively
/// rendered as `"0"` (which a real pid never is).
fn format_pid_decimal(pid: i32, buf: &mut [u8; MAX_PID_DIGITS]) -> &[u8] {
    // A real pid is always positive; clamp anything else to 0 defensively.
    let mut n = u32::try_from(pid).unwrap_or(0);
    // Fill the buffer back-to-front (least-significant digit first), then return
    // the populated trailing slice.
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    }
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    &buf[i..]
}

/// Write the requested limit knobs into the leaf at `path`.
fn write_knobs(path: &Path, limits: &ResourceLimits) -> Result<()> {
    if let Some(max) = limits.memory_bytes {
        // Forbid the swap escape hatch first, then set the ceiling itself.
        write_knob(path, "memory.swap.max", "0")?;
        write_knob(path, "memory.max", &max.to_string())?;
        // On OOM, take down the whole box together rather than letting the
        // kernel pick one member to sacrifice.
        write_knob(path, "memory.oom.group", "1")?;
        // No memory.high on purpose — see the module docs: with swap forbidden
        // it stalls a runaway allocator instead of killing it.
    }
    if let Some(percent) = limits.cpu_max_percent {
        write_knob(path, "cpu.max", &cpu_max_knob_value(percent))?;
    }
    if let Some(procs) = limits.max_procs {
        write_knob(path, "pids.max", &procs.to_string())?;
    }
    Ok(())
}

/// cgroup v2 `cpu.max` period, in microseconds. A 100 ms period is the kernel
/// default and keeps the quota arithmetic exact for whole-percent limits.
const PERIOD_US: u64 = 100_000;

/// Render a percent-of-one-core limit to a cgroup v2 `cpu.max` value.
///
/// `cpu.max` is `"<quota_us> <period_us>"`: the cgroup may use at most `quota_us`
/// microseconds of CPU per `period_us`. With the fixed [`PERIOD_US`] period,
/// percent-of-one-core maps to `quota = percent * (PERIOD_US / 100)`
/// (`100%` → `100000 100000` = one full core; `150%` → `150000 100000` = one and
/// a half cores; `50%` → `50000 100000` = half a core). This caps the *rate*, so
/// a runaway can spin forever but never starve the host. `saturating_mul` keeps
/// an absurd percent from wrapping; the kernel rejects nonsense quotas regardless.
fn cpu_max_knob_value(percent: u64) -> String {
    let quota_us = percent.saturating_mul(PERIOD_US / 100);
    format!("{quota_us} {PERIOD_US}")
}

fn write_knob(path: &Path, knob: &str, value: &str) -> Result<()> {
    let file = path.join(knob);
    fs::write(&file, value).map_err(|e| {
        NonoError::SandboxInit(format!(
            "resource: failed to write '{value}' to {} ({e}); \
             is the cgroup v2 controller delegated?",
            file.display()
        ))
    })
}

/// Kill anything still in the leaf, then remove it. Best-effort: leaking an
/// empty cgroup directory is not worth failing a completed run over.
fn teardown(path: &Path) {
    // cgroup.kill (Linux 5.14+) kills the whole subtree atomically. Ignored if
    // unavailable; for a reaped single process the leaf is already empty.
    let _ = fs::write(path.join("cgroup.kill"), "1");
    // A cgroup with live members cannot be removed; wait briefly for the kernel
    // to reap before rmdir.
    let procs = path.join("cgroup.procs");
    for _ in 0..50 {
        match fs::read_to_string(&procs) {
            Ok(contents) if contents.trim().is_empty() => break,
            Ok(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            Err(_) => break,
        }
    }
    let _ = fs::remove_dir(path);
}

/// Find the cgroup directory we're allowed to create our box inside.
///
/// On a normal login, systemd hands each user's session a private cgroup subtree
/// it may manage without root — rooted at `.../user@<uid>.service`. That handover
/// is "delegation", and that directory is the only place we can reliably create
/// child cgroups. We locate it by reading our own cgroup path from
/// `/proc/self/cgroup` and walking up to the `user@<uid>.service` ancestor.
fn delegated_base() -> Result<PathBuf> {
    let raw = fs::read_to_string("/proc/self/cgroup").map_err(|e| {
        NonoError::SandboxInit(format!("resource: cannot read /proc/self/cgroup: {e}"))
    })?;
    let uid = nix::unistd::Uid::current().as_raw();
    let base = parse_delegated_base(&raw, uid)?;
    if !base.is_dir() {
        return Err(NonoError::SandboxInit(format!(
            "resource: delegated cgroup path {} does not exist",
            base.display()
        )));
    }
    Ok(base)
}

/// Pure parser for [`delegated_base`]: take the `/proc/self/cgroup` contents and
/// the uid, return the absolute path of the `user@<uid>.service` ancestor.
fn parse_delegated_base(proc_self_cgroup: &str, uid: u32) -> Result<PathBuf> {
    // Unified cgroup v2 exposes a single `0::<path>` line.
    let rel = proc_self_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| {
            NonoError::SandboxInit(
                "resource: not a unified cgroup v2 hierarchy (no '0::' line in \
                 /proc/self/cgroup); cgroup resource limits are unavailable"
                    .to_string(),
            )
        })?
        .trim();

    let marker = format!("user@{uid}.service");
    // Keep the path up to and including the user@<uid>.service segment — the
    // systemd delegation boundary we can create children under.
    let mut acc = PathBuf::from("/sys/fs/cgroup");
    let mut found = false;
    for segment in rel.split('/').filter(|s| !s.is_empty()) {
        acc.push(segment);
        if segment == marker {
            found = true;
            break;
        }
    }
    if !found {
        return Err(NonoError::SandboxInit(format!(
            "resource: no delegated cgroup v2 subtree for this session \
             (expected a '{marker}' ancestor in '{rel}'); resource limits \
             require a delegated user session (systemd Delegate=yes)"
        )));
    }
    Ok(acc)
}

/// Verify the delegation pushed the controllers we need into its children
/// (`cgroup.subtree_control`); without that the leaf's `memory.max`/`pids.max`
/// files would not exist and a cap would silently fail to apply.
fn ensure_controllers_delegated(base: &Path, limits: &ResourceLimits) -> Result<()> {
    let subtree_path = base.join("cgroup.subtree_control");
    let subtree = fs::read_to_string(&subtree_path).map_err(|e| {
        NonoError::SandboxInit(format!(
            "resource: cannot read {} ({e})",
            subtree_path.display()
        ))
    })?;
    let has = |controller: &str| subtree.split_whitespace().any(|w| w == controller);

    if limits.memory_bytes.is_some() && !has("memory") {
        return Err(NonoError::SandboxInit(format!(
            "resource: the 'memory' controller is not delegated to {} \
             (cgroup.subtree_control = '{}'); cannot enforce --memory",
            base.display(),
            subtree.trim()
        )));
    }
    if limits.cpu_max_percent.is_some() && !has("cpu") {
        return Err(NonoError::SandboxInit(format!(
            "resource: the 'cpu' controller is not delegated to {} \
             (cgroup.subtree_control = '{}'); cannot enforce --cpu-max",
            base.display(),
            subtree.trim()
        )));
    }
    if limits.max_procs.is_some() && !has("pids") {
        return Err(NonoError::SandboxInit(format!(
            "resource: the 'pids' controller is not delegated to {} \
             (cgroup.subtree_control = '{}'); cannot enforce --max-procs",
            base.display(),
            subtree.trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{MAX_PID_DIGITS, cpu_max_knob_value, format_pid_decimal, parse_delegated_base};
    use std::path::PathBuf;

    /// The percent-of-one-core limit must render to the exact cgroup `cpu.max`
    /// "<quota> <period>" the kernel expects, against a fixed 100ms period.
    #[test]
    fn cpu_max_value_maps_percent_to_quota_over_period() {
        assert_eq!(cpu_max_knob_value(100), "100000 100000"); // one full core
        assert_eq!(cpu_max_knob_value(50), "50000 100000"); // half a core
        assert_eq!(cpu_max_knob_value(150), "150000 100000"); // one and a half cores
        assert_eq!(cpu_max_knob_value(200), "200000 100000"); // two cores
        assert_eq!(cpu_max_knob_value(1), "1000 100000"); // 1% of a core
    }

    #[test]
    fn parses_user_service_ancestor_from_deep_path() {
        let raw = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/\
                   app-org.gnome.Terminal.slice/vte-spawn-abc.scope\n";
        let base = parse_delegated_base(raw, 1000).expect("should parse");
        assert_eq!(
            base,
            PathBuf::from("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service")
        );
    }

    #[test]
    fn stops_at_user_service_even_when_it_is_the_leaf() {
        let raw = "0::/user.slice/user-501.slice/user@501.service\n";
        let base = parse_delegated_base(raw, 501).expect("should parse");
        assert_eq!(
            base,
            PathBuf::from("/sys/fs/cgroup/user.slice/user-501.slice/user@501.service")
        );
    }

    #[test]
    fn rejects_non_unified_hierarchy() {
        // A v1/hybrid line has a non-zero hierarchy id and named controllers.
        let raw = "1:name=systemd:/user.slice/session-2.scope\n";
        assert!(parse_delegated_base(raw, 1000).is_err());
    }

    #[test]
    fn rejects_session_without_user_service_delegation() {
        // e.g. launched from a system service: no user@<uid>.service ancestor.
        let raw = "0::/system.slice/cron.service\n";
        assert!(parse_delegated_base(raw, 1000).is_err());
    }

    #[test]
    fn rejects_mismatched_uid() {
        // The path is for uid 1000 but we are uid 1001 — not our delegation.
        let raw = "0::/user.slice/user-1000.slice/user@1000.service/app.slice\n";
        assert!(parse_delegated_base(raw, 1001).is_err());
    }

    /// The self-attach write depends on a correct, allocation-free decimal
    /// rendering of the child's pid; spot-check the encoder across widths.
    #[test]
    fn formats_pid_as_decimal() {
        let mut buf = [0u8; MAX_PID_DIGITS];
        assert_eq!(format_pid_decimal(1, &mut buf), b"1");
        assert_eq!(format_pid_decimal(7, &mut buf), b"7");
        assert_eq!(format_pid_decimal(12345, &mut buf), b"12345");
        assert_eq!(format_pid_decimal(i32::MAX, &mut buf), b"2147483647");
    }

    #[test]
    fn formats_nonpositive_pid_defensively_as_zero() {
        let mut buf = [0u8; MAX_PID_DIGITS];
        assert_eq!(format_pid_decimal(0, &mut buf), b"0");
        assert_eq!(format_pid_decimal(-1, &mut buf), b"0");
    }
}
