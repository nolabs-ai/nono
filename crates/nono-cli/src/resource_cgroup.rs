//! Linux cgroup v2 memory enforcement.
//!
//! A `--memory` limit runs the program in a *cgroup leaf*: a directory under
//! `/sys/fs/cgroup` whose limits are set by writing to files ("knobs"). If the
//! program and its children exceed the limit, the kernel kills them all — and only
//! them. The supervisor builds the leaf before forking; the child moves itself in;
//! the leaf is deleted when the run ends.
//!
//! # Why the child moves itself in
//!
//! A forked child starts in its parent's cgroup, and a cgroup caps all its
//! processes together — so once one process is in, everything it spawns is capped
//! too. Moving the child in *after* `fork()` would leave a gap where it runs
//! uncapped. Instead the parent opens `cgroup.procs` before forking and the child
//! writes its own pid to it first thing. See [`child_self_attach`].
//!
//! # Fail-closed (AGENTS.md "Fail Secure")
//!
//! If the leaf can't be built or entered, the run is refused. Setup is pre-fork, so
//! failures surface as a [`NonoError`] before anything runs; a child that can't get
//! in `_exit(126)`s before running the program.
//!
//! # The knobs
//!
//! - `memory.max`         — the hard limit; over it, the kernel OOM-kills.
//! - `memory.swap.max=0`  — no swap (else a program could swap around the limit).
//! - `memory.oom.group=1` — kill the whole leaf together, not one process.
//!
//! `memory.high` is left unset on purpose: with swap off, a program over the limit
//! would stall instead of being killed quickly.
//!
//! Other backends (WSL2 / non-systemd) come later; this targets the common case, a
//! systemd `Delegate=yes` session.

use nix::libc;
use nono::{NonoError, ResourceLimits, Result};
use std::fs::{self, File, OpenOptions};
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

/// Leaf directory name prefix (`nono.<pid>`), shared by creation and
/// [`parse_leaf_pid`] so the two can't drift.
const LEAF_PREFIX: &str = "nono.";

/// This module's standard error: a [`NonoError::SandboxInit`] with the shared
/// `resource: ` prefix. The per-site detail stays at the call site.
fn resource_err(msg: impl Into<String>) -> NonoError {
    NonoError::SandboxInit(format!("resource: {}", msg.into()))
}

/// One run's memory limit: a cgroup v2 directory we create, arm, and delete on drop.
///
/// Built before the fork by [`CgroupLeaf::create`]; the child moves itself in (see
/// [`child_self_attach`]). Drop kills any survivors and removes the directory.
pub struct CgroupLeaf {
    /// Absolute path of the leaf directory, e.g.
    /// `/sys/fs/cgroup/.../user@1000.service/nono.<pid>`.
    path: PathBuf,
    /// Write handle to `cgroup.procs`, opened pre-fork so the child inherits it and
    /// can move itself in. `O_CLOEXEC`, so it closes when the child execs.
    procs: File,
}

/// Proof the kernel OOM-killed something in this leaf (read from `memory.events`,
/// plus the limit/peak), so a bare SIGKILL can be explained as "you hit the limit".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OomReport {
    /// Processes the kernel killed here for exceeding the limit (`oom_kill`).
    pub oom_kills: u64,
    /// Whole-leaf kills (`oom_group_kill`, our `memory.oom.group=1`). Always 0
    /// before kernel 5.14, which doesn't report it.
    pub oom_group_kills: u64,
    /// The limit (`memory.max`) in bytes, if still readable.
    pub limit_bytes: Option<u64>,
    /// Peak memory reached (`memory.peak`) in bytes, if the kernel reports it
    /// (Linux 5.19+).
    pub peak_bytes: Option<u64>,
}

impl CgroupLeaf {
    /// Create the leaf, arm it, and open `cgroup.procs` for the child. Pre-fork;
    /// fails closed.
    ///
    /// # Errors
    /// [`NonoError::SandboxInit`] if there's no manageable cgroup v2 subtree, the
    /// memory controller is missing, or a write/open fails. Nothing half-built is
    /// left behind.
    pub fn create(limits: &ResourceLimits) -> Result<Self> {
        let base = delegated_base()?;
        ensure_controllers_delegated(&base, limits)?;

        // Clean up leaves left over from earlier runs whose supervisor was killed
        // before it could tidy up. Best-effort; also frees the name in case a pid
        // gets reused.
        sweep_stale_leaves(&base);

        let path = base.join(format!("{LEAF_PREFIX}{}", std::process::id()));
        // If a leaf with our exact pid already exists (a pid reused after a crash),
        // it might still hold old processes, so fail rather than quietly reuse it.
        fs::create_dir(&path).map_err(|e| {
            resource_err(format!(
                "failed to create cgroup leaf {}: {e}",
                path.display()
            ))
        })?;

        // The directory exists now, so anything that fails past this point has to
        // remove it. `arm` does the remaining fallible work; on error we tear the
        // directory down (there's no `Self` yet, so it can't be torn down twice).
        Self::arm(path.clone(), limits).inspect_err(|_| teardown(&path))
    }

    /// Write the limits and open `cgroup.procs`. Split from [`create`](Self::create)
    /// so a failure here is cleaned up by the caller's teardown of the directory.
    fn arm(path: PathBuf, limits: &ResourceLimits) -> Result<Self> {
        write_knobs(&path, limits)?;
        let procs_path = path.join("cgroup.procs");
        // Close-on-exec (`O_CLOEXEC`, Rust's default) is on purpose: the child
        // inherits this open file across `fork` so it can add itself, and the
        // kernel then closes it when the child starts the real program, so it never
        // leaks into the sandboxed code.
        let procs = OpenOptions::new()
            .write(true)
            .open(&procs_path)
            .map_err(|e| {
                resource_err(format!(
                    "failed to open {} for self-attach: {e}",
                    procs_path.display()
                ))
            })?;
        // Log that the limit is in effect (and where) so a verbose run (`-v` /
        // RUST_LOG) shows it; the user already sees it in the capabilities block.
        tracing::info!(
            "resource: enforcing {} via cgroup v2 leaf {}",
            limits.summary(),
            path.display()
        );
        Ok(Self { path, procs })
    }

    /// Raw fd of `cgroup.procs` for the child to inherit (see [`child_self_attach`]).
    /// Valid while this `CgroupLeaf` lives.
    #[must_use]
    pub fn procs_raw_fd(&self) -> RawFd {
        self.procs.as_raw_fd()
    }

    /// Read OOM evidence from `memory.events` — call after the child exits, before
    /// teardown. `Some` only if the kernel actually recorded an OOM kill here.
    ///
    /// Never fails: an unreadable file yields `None` or an empty field.
    #[must_use]
    pub fn oom_report(&self) -> Option<OomReport> {
        let events = fs::read_to_string(self.path.join("memory.events")).ok()?;
        let oom_kills = event_counter(&events, "oom_kill");
        let oom_group_kills = event_counter(&events, "oom_group_kill");
        // No OOM kill here: the limit wasn't the cause, so say nothing.
        if oom_kills == 0 && oom_group_kills == 0 {
            return None;
        }
        let gauge = |knob: &str| -> Option<u64> {
            fs::read_to_string(self.path.join(knob))
                .ok()?
                .trim()
                .parse::<u64>()
                .ok()
        };
        Some(OomReport {
            oom_kills,
            oom_group_kills,
            limit_bytes: gauge("memory.max"),
            peak_bytes: gauge("memory.peak"),
        })
    }
}

/// Read one `key value` counter (e.g. `oom_kill`) from `memory.events`. A missing
/// or non-numeric key reads as 0.
fn event_counter(events: &str, key: &str) -> u64 {
    events
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(' ')?;
            if name == key {
                value.trim().parse::<u64>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0)
}

impl Drop for CgroupLeaf {
    fn drop(&mut self) {
        teardown(&self.path);
    }
}

/// Move the child into the cgroup by writing its pid to the inherited
/// `cgroup.procs` fd — after the fork, before it sandboxes or execs. Doing it first
/// means every later child is capped too, with no gap to escape the parent's cgroup.
///
/// Async-signal-safe (only `getpid`, a stack buffer, and `write` — no alloc, no
/// locks). Returns `true` on a complete write; on `false` the caller must `_exit`
/// the child (fail closed).
///
/// # Safety
/// `procs_fd` must be a valid, writable `cgroup.procs` fd inherited across `fork`.
#[must_use = "on `false` the child is unconfined and the caller MUST _exit it (fail-closed)"]
pub fn child_self_attach(procs_fd: RawFd) -> bool {
    // SAFETY: `getpid` is async-signal-safe and always succeeds; in the child it
    // returns the child's own pid.
    let pid = unsafe { libc::getpid() };
    let mut buf = [0u8; MAX_PID_DIGITS];
    let encoded = format_pid_decimal(pid, &mut buf);
    // SAFETY: writing a stack buffer to a raw fd is async-signal-safe. A short or
    // failed write is treated as failure, so the caller fails closed.
    let written = unsafe {
        libc::write(
            procs_fd,
            encoded.as_ptr().cast::<libc::c_void>(),
            encoded.len(),
        )
    };
    written == encoded.len() as isize
}

/// Widest decimal a pid needs: `i32::MAX` is 10 digits.
const MAX_PID_DIGITS: usize = 10;

/// Write `pid` as decimal ASCII into `buf` without allocating (async-signal-safe);
/// returns the filled slice. A non-positive `pid` renders as `"0"` (a real one
/// never is).
fn format_pid_decimal(pid: i32, buf: &mut [u8; MAX_PID_DIGITS]) -> &[u8] {
    let mut n = u32::try_from(pid).unwrap_or(0);
    // Write the digits from the right end of buf, lowest digit first, so there's
    // no need for a second pass to reverse them.
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

/// Write the requested memory limits into the leaf at `path`.
fn write_knobs(path: &Path, limits: &ResourceLimits) -> Result<()> {
    if let Some(max) = limits.memory_bytes {
        // Turn off swap before setting the limit, so the program can't use swap to
        // get around it.
        write_knob(path, "memory.swap.max", "0")?;
        write_knob(path, "memory.max", &max.to_string())?;
        // On an OOM kill, take down the whole leaf at once rather than a single
        // process the kernel picks.
        write_knob(path, "memory.oom.group", "1")?;
        // We leave memory.high unset on purpose (see the module docs): with swap
        // off it would make a runaway program stall instead of dying quickly.
    }
    Ok(())
}

fn write_knob(path: &Path, knob: &str, value: &str) -> Result<()> {
    let file = path.join(knob);
    fs::write(&file, value).map_err(|e| {
        resource_err(format!(
            "failed to write '{value}' to {} ({e}); \
             is the cgroup v2 controller delegated?",
            file.display()
        ))
    })
}

/// How long to wait for the kernel to reap killed processes before `rmdir`:
/// [`REAP_POLL_ATTEMPTS`] checks [`REAP_POLL_INTERVAL`] apart (~500ms). Usually the
/// child is already gone, so the first check passes.
const REAP_POLL_ATTEMPTS: u32 = 50;
const REAP_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

/// Kill anything left in the leaf, then remove it. Best-effort — a leftover empty
/// directory isn't worth failing a finished run over.
fn teardown(path: &Path) {
    // cgroup.kill (Linux 5.14+) kills everything in the leaf at once. If it isn't
    // available we ignore it; a single process that already exited leaves the leaf
    // empty anyway.
    let _ = fs::write(path.join("cgroup.kill"), "1");
    // A cgroup that still has processes in it can't be removed, so wait briefly for
    // the kernel to clean them up before rmdir (see the poll limits above).
    let procs = path.join("cgroup.procs");
    for _ in 0..REAP_POLL_ATTEMPTS {
        match fs::read_to_string(&procs) {
            // Still has processes: give the kernel a moment, then check again.
            Ok(contents) if !contents.trim().is_empty() => std::thread::sleep(REAP_POLL_INTERVAL),
            // Empty (cleaned up) or unreadable (already gone): stop and rmdir.
            _ => break,
        }
    }
    if let Err(e) = fs::remove_dir(path) {
        // If we still can't remove the leaf (processes outlived the wait), we leave
        // behind an empty cgroup directory. Not fatal — the next run sweeps it up —
        // but worth a warning since it's otherwise invisible.
        tracing::warn!(
            "resource: could not remove cgroup leaf {} ({e}); it may leak until a later run sweeps it",
            path.display()
        );
    }
}

/// Remove leftover `nono.<pid>` leaves whose supervisor is gone (e.g. SIGKILL'd
/// before teardown ran). Best-effort, and only touches leaves whose pid is dead, so
/// a live nono (or a reused pid) is left alone.
fn sweep_stale_leaves(base: &Path) {
    let Ok(entries) = fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(parse_leaf_pid) else {
            continue;
        };
        if !pid_is_alive(pid) {
            teardown(&entry.path());
        }
    }
}

/// Supervisor pid from a leaf name (`nono.<pid>`), or `None` if it isn't one of ours.
fn parse_leaf_pid(name: &str) -> Option<u32> {
    name.strip_prefix(LEAF_PREFIX)?.parse::<u32>().ok()
}

/// Whether `pid` still exists (`/proc/<pid>` present), in any state including zombie.
fn pid_is_alive(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

/// Find the cgroup directory we may create our leaf in.
///
/// systemd delegates each user session a subtree under `.../user@<uid>.service` it
/// can manage without root — the one place we can reliably create child cgroups. We
/// read `/proc/self/cgroup` and walk up to it.
fn delegated_base() -> Result<PathBuf> {
    let raw = fs::read_to_string("/proc/self/cgroup")
        .map_err(|e| resource_err(format!("cannot read /proc/self/cgroup: {e}")))?;
    let uid = nix::unistd::Uid::current().as_raw();
    let base = parse_delegated_base(&raw, uid)?;
    if !base.is_dir() {
        return Err(resource_err(format!(
            "delegated cgroup path {} does not exist",
            base.display()
        )));
    }
    Ok(base)
}

/// Pure parser for [`delegated_base`]: from `/proc/self/cgroup` contents and the
/// uid, return the absolute path of the `user@<uid>.service` ancestor.
fn parse_delegated_base(proc_self_cgroup: &str, uid: u32) -> Result<PathBuf> {
    // A pure cgroup v2 system has a single `0::<path>` line.
    let rel = proc_self_cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| {
            resource_err(
                "not a unified cgroup v2 hierarchy (no '0::' line in \
                 /proc/self/cgroup); cgroup resource limits are unavailable",
            )
        })?
        .trim();

    let marker = format!("user@{uid}.service");
    // Build the path up to and including the user@<uid>.service segment — the point
    // systemd lets us create cgroups under. Match it as a whole path segment, never
    // as a substring (see the adversarial-lookalike tests).
    let mut acc = PathBuf::from("/sys/fs/cgroup");
    for segment in rel.split('/').filter(|s| !s.is_empty()) {
        acc.push(segment);
        if segment == marker {
            return Ok(acc);
        }
    }
    Err(resource_err(format!(
        "no delegated cgroup v2 subtree for this session \
         (expected a '{marker}' ancestor in '{rel}'); resource limits \
         require a delegated user session (systemd Delegate=yes)"
    )))
}

/// Check the memory controller is enabled for child cgroups. A cgroup only has a
/// controller's files (e.g. `memory.max`) if it's listed in the parent's
/// `cgroup.subtree_control`; otherwise the limit would silently not apply.
fn ensure_controllers_delegated(base: &Path, limits: &ResourceLimits) -> Result<()> {
    let subtree_path = base.join("cgroup.subtree_control");
    let subtree = fs::read_to_string(&subtree_path)
        .map_err(|e| resource_err(format!("cannot read {}: {e}", subtree_path.display())))?;
    let controller_enabled = |c: &str| subtree.split_whitespace().any(|w| w == c);

    if limits.memory_bytes.is_some() && !controller_enabled("memory") {
        return Err(resource_err(format!(
            "the 'memory' controller is not delegated to {} \
             (cgroup.subtree_control = '{}'); cannot enforce --memory",
            base.display(),
            subtree.trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{MAX_PID_DIGITS, format_pid_decimal, parse_delegated_base};
    use std::path::PathBuf;

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

    /// Self-attach depends on a correct, allocation-free pid encoding; spot-check
    /// the encoder across widths.
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

    /// `oom_report` reads these counters to drive the "you hit the memory cap"
    /// message, so the parser must pull the right line and treat a missing or junk
    /// key as 0 (never panic on a partial/extended file).
    #[test]
    fn event_counter_reads_named_lines_and_defaults_missing_to_zero() {
        use super::event_counter;

        // A representative cgroup v2 memory.events table.
        let events = "low 0\nhigh 0\nmax 12\noom 3\noom_kill 2\noom_group_kill 1\n";
        assert_eq!(event_counter(events, "oom_kill"), 2);
        assert_eq!(event_counter(events, "oom_group_kill"), 1);
        assert_eq!(event_counter(events, "max"), 12);
        // An absent key reads as 0, so a kernel without oom_group_kill is fine.
        assert_eq!(event_counter(events, "oom_group_kill_missing"), 0);
        assert_eq!(event_counter("", "oom_kill"), 0);
        // A non-numeric value is ignored rather than panicking.
        assert_eq!(event_counter("oom_kill notanumber\n", "oom_kill"), 0);
        // A prefix of a real key must not match (whole-key, space-delimited).
        assert_eq!(event_counter("oom_killer 9\n", "oom_kill"), 0);
    }

    #[test]
    fn parse_leaf_pid_only_matches_our_leaves() {
        use super::parse_leaf_pid;
        assert_eq!(parse_leaf_pid("nono.123"), Some(123));
        assert_eq!(parse_leaf_pid("nono.0"), Some(0));
        assert_eq!(parse_leaf_pid("nono.4194304"), Some(4_194_304));
        // Malformed or not one of our leaves.
        assert_eq!(parse_leaf_pid("nono."), None);
        assert_eq!(parse_leaf_pid("nono.abc"), None);
        assert_eq!(parse_leaf_pid("nono.12.3"), None);
        assert_eq!(parse_leaf_pid("nono.-1"), None);
        assert_eq!(parse_leaf_pid("nonoX.5"), None);
        assert_eq!(parse_leaf_pid("user@1000.service"), None);
    }

    #[test]
    fn pid_is_alive_tracks_real_processes() {
        use super::pid_is_alive;
        // Our own pid is alive; a value above the kernel pid_max never is.
        assert!(pid_is_alive(std::process::id()));
        assert!(!pid_is_alive(u32::MAX));
    }

    // ---- Adversarial component-wise matching & pid property ----

    /// SECURITY: we match the delegation boundary as a whole path segment
    /// (`segment == marker`), never as a substring. A `starts_with` or `contains`
    /// check would wrongly accept these near-miss segments and return a directory
    /// outside the real `user@<uid>.service` delegation (AGENTS.md: `starts_with`
    /// on paths is a vulnerability). All of these must be REJECTED for uid 1000.
    #[test]
    fn rejects_adversarial_segment_lookalikes_componentwise() {
        let poisoned = [
            // marker with extra text added to the end of the same segment
            "0::/user.slice/user-1000.slice/user@1000.service.evil/app.slice\n",
            "0::/user.slice/user-1000.slice/user@1000.serviceX\n",
            // marker as the end of a longer segment
            "0::/user.slice/user-1000.slice/xuser@1000.service/app.slice\n",
            "0::/user.slice/user-1000.slice/evil-user@1000.service\n",
            // marker in the middle of a segment (a `contains` check would accept it)
            "0::/user.slice/prefixuser@1000.servicesuffix/app.slice\n",
            // an underscore instead of the separating slash — looks similar, isn't
            "0::/user.slice/user@1000_service\n",
            // a stray space leaves extra text on the segment; split('/') doesn't
            // split on spaces, so the segment is "user@1000.service junk".
            "0::/user.slice/user@1000.service junk/app.scope\n",
        ];
        for raw in poisoned {
            assert!(
                parse_delegated_base(raw, 1000).is_err(),
                "adversarial lookalike segment must NOT match the delegation boundary: {raw:?}"
            );
        }
    }

    /// SECURITY: the uid is baked into the marker (`user@<uid>.service`) and must
    /// match a whole segment. uid 100's `user@100.service` must NOT match a
    /// `user@1000.service` segment (100 is a substring of 1000), and vice versa.
    #[test]
    fn rejects_uid_that_is_substring_of_another_uid() {
        // Path delegates uid 1000; asking as uid 100 (a substring) must fail.
        let raw_1000 = "0::/user.slice/user-1000.slice/user@1000.service/app.slice\n";
        assert!(
            parse_delegated_base(raw_1000, 100).is_err(),
            "uid 100 must not borrow uid 1000's delegation (substring match)"
        );
        // Symmetric: path delegates uid 100; asking as uid 1000 must fail.
        let raw_100 = "0::/user.slice/user-100.slice/user@100.service/app.slice\n";
        assert!(
            parse_delegated_base(raw_100, 1000).is_err(),
            "uid 1000 must not match uid 100's delegation"
        );
        // Exact uid still works (guards against the test over-rejecting).
        let base = parse_delegated_base(raw_1000, 1000).expect("exact uid must match");
        assert_eq!(
            base,
            PathBuf::from("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service")
        );
    }

    /// The marker can sit at an interior position with descendants below it; the
    /// base must be truncated to exactly the marker (the delegation boundary), even
    /// with a trailing slash and a non-first `0::` line.
    #[test]
    fn parses_marker_as_nonfinal_segment_and_truncates_exactly() {
        let raw = "1:name=systemd:/legacy/ignored\n\
                   0::/user.slice/user-1000.slice/user@1000.service/app.slice/svc.scope\n";
        let base = parse_delegated_base(raw, 1000).expect("should parse");
        assert_eq!(
            base,
            PathBuf::from("/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service"),
            "base must stop at the marker even with descendants below it"
        );

        // Trailing slash after the marker: split('/').filter(non-empty) drops the
        // empty tail, so the result is identical.
        let raw_slash = "0::/user.slice/user@1000.service/\n";
        let base_slash = parse_delegated_base(raw_slash, 1000).expect("should parse");
        assert_eq!(
            base_slash,
            PathBuf::from("/sys/fs/cgroup/user.slice/user@1000.service")
        );
    }

    /// `format_pid_decimal` matters (the post-fork child writes its pid through it
    /// to add itself), so it must give the same result as `i32::to_string()` for
    /// every positive pid — including where the digit count changes and the exact
    /// buffer fill at `i32::MAX` (10 digits == MAX_PID_DIGITS), with `to_string` as
    /// the reference.
    #[test]
    fn format_pid_decimal_matches_to_string_over_wide_range_and_boundaries() {
        let mut buf = [0u8; MAX_PID_DIGITS];

        // Explicit boundaries: digit-count transitions + exact buffer fill.
        for &pid in &[
            1i32,
            9,
            10,
            99,
            100,
            999,
            1000,
            9999,
            10000,
            1_000_000,
            i32::MAX,
        ] {
            assert_eq!(
                format_pid_decimal(pid, &mut buf),
                pid.to_string().as_bytes(),
                "pid {pid} must encode identically to to_string()"
            );
        }
        // i32::MAX fills the buffer exactly: 10 digits, no leading slack.
        assert_eq!(format_pid_decimal(i32::MAX, &mut buf).len(), MAX_PID_DIGITS);

        // Dense sweep over a contiguous low range (covers the 9->10, 99->100,
        // 999->1000 width transitions).
        for pid in 1..=10_000_i32 {
            assert_eq!(
                format_pid_decimal(pid, &mut buf),
                pid.to_string().as_bytes(),
                "mismatch at pid {pid}"
            );
        }
        // Wide property sweep across the positive i32 range (a prime stride avoids
        // aliasing to round numbers while staying fast).
        let mut pid: i64 = 1;
        while pid <= i32::MAX as i64 {
            let p = pid as i32;
            assert_eq!(format_pid_decimal(p, &mut buf), p.to_string().as_bytes());
            pid += 7919;
        }

        // Non-positive defensively renders as "0" (a real pid never is); i32::MIN
        // is included because a naive `pid.abs()` would overflow/panic.
        for pid in [0_i32, -1, -42, -2_147_483_647, i32::MIN] {
            assert_eq!(
                format_pid_decimal(pid, &mut buf),
                b"0",
                "non-positive pid {pid} must render as 0"
            );
        }
    }

    // ---- Live cgroup v2 enforcement tests ----
    //
    // #[ignore]-gated (not run in CI): they create real leaves under
    // /sys/fs/cgroup, run a small program that deliberately overruns the limit, and
    // read kernel files. The host must be a systemd `Delegate=yes` user session
    // with the `memory` controller delegated to `user@<uid>.service`. Each creates
    // a `nono.<pid>` leaf for this test process, so run them SERIALLY — in parallel
    // they collide on the name:
    //
    //   cargo test -p nono-cli --bins -- --ignored --test-threads=1
    //
    // or one at a time, e.g.:
    //
    //   cargo test -p nono-cli --bins -- --ignored live_child_over_memory_cap

    /// LIVE: end-to-end enforcement. A forked child that self-attaches then
    /// allocates past the cap is OOM-killed (SIGKILL); the leaf records
    /// oom_kill>=1; swap stayed at 0 (no escape); the parent survives; teardown
    /// removes the leaf. The limiter's core security property, on a real cgroupfs.
    #[test]
    #[ignore = "requires live cgroup v2 delegation (memory controller); run with --ignored"]
    fn live_child_over_memory_cap_is_oom_killed_and_only_it() {
        use super::CgroupLeaf;
        use super::child_self_attach;
        use nix::libc;
        use nix::sys::signal::Signal;
        use nix::sys::wait::{WaitStatus, waitpid};
        use nix::unistd::{ForkResult, fork};
        use nono::ResourceLimits;

        const CAP: u64 = 64 * 1024 * 1024; // 64 MiB hard ceiling
        const TOUCH: usize = 128 * 1024 * 1024; // mmap + fault in 128 MiB (2x cap)
        const PAGE: usize = 4096;

        let limits = ResourceLimits {
            memory_bytes: Some(CAP),
        };
        // Real pre-fork construction: creates the leaf dir, writes
        // memory.swap.max=0 / memory.max=CAP / memory.oom.group=1, opens
        // cgroup.procs for the child to inherit.
        let leaf = CgroupLeaf::create(&limits).expect("create leaf on delegated host");
        let procs_fd = leaf.procs_raw_fd();
        let leaf_path = leaf.path.clone(); // private field — reachable in-module

        // SAFETY: single-purpose forked child; after fork it uses only
        // async-signal-safe libc calls (no Rust heap alloc, no locks) — exactly
        // the constraint child_self_attach is built for.
        match unsafe { fork() }.expect("fork") {
            ForkResult::Child => {
                // Self-attach FIRST, before allocating, mirroring the supervisor.
                if !child_self_attach(procs_fd) {
                    unsafe { libc::_exit(126) };
                }
                // Allocate anonymous memory and fault one byte per page so the
                // kernel actually charges it to memory.current.
                let addr = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        TOUCH,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                        -1,
                        0,
                    )
                };
                if addr == libc::MAP_FAILED {
                    unsafe { libc::_exit(50) };
                }
                let base = addr.cast::<u8>();
                let mut off = 0usize;
                while off < TOUCH {
                    // Touch the page; the kernel OOM-kills us (SIGKILL) the moment
                    // resident memory crosses CAP, so this loop never completes.
                    unsafe { *base.add(off) = 0xA5 };
                    off += PAGE;
                }
                // If we somehow survive the cap, exit 0 so the parent's SIGKILL
                // assertion FAILS loudly (the cap did not enforce).
                unsafe { libc::_exit(0) };
            }
            ForkResult::Parent { child } => {
                let status = waitpid(child, None).expect("waitpid");
                // The child must be KILLED by the kernel, not exit cleanly.
                match status {
                    WaitStatus::Signaled(_, Signal::SIGKILL, _) => {}
                    other => {
                        panic!("expected child SIGKILL (OOM), got {other:?}; cap did not enforce")
                    }
                }

                // Kernel-side evidence: the leaf recorded an OOM kill.
                let events = std::fs::read_to_string(leaf_path.join("memory.events"))
                    .expect("read memory.events");
                let oom_kill = events
                    .lines()
                    .find_map(|l| l.strip_prefix("oom_kill "))
                    .and_then(|n| n.trim().parse::<u64>().ok())
                    .expect("memory.events has an oom_kill line");
                assert!(
                    oom_kill >= 1,
                    "expected oom_kill>=1 in memory.events, got {oom_kill} (full: {events:?})"
                );

                // The swap escape hatch stayed shut: nothing spilled to swap.
                let swap = std::fs::read_to_string(leaf_path.join("memory.swap.current"))
                    .expect("read memory.swap.current");
                assert_eq!(
                    swap.trim(),
                    "0",
                    "memory.swap.current must be 0 (swap.max=0 forbids the escape)"
                );
                // Reaching here at all proves the parent survived the child OOM
                // kill: oom.group scoped the kill to the leaf, not this process.
            }
        }

        // The supervisor reads the same evidence via oom_report() to drive the
        // user-facing diagnostic: it must report the kill and echo the cap.
        let report = leaf
            .oom_report()
            .expect("oom_report must surface the recorded OOM kill");
        assert!(report.oom_kills >= 1, "oom_report.oom_kills must be >= 1");
        assert_eq!(
            report.limit_bytes,
            Some(CAP),
            "oom_report must echo the enforced memory.max"
        );

        // Drop runs teardown: kill survivors, rmdir the leaf.
        drop(leaf);
        // Fail-closed cleanup is observable: the leaf directory is gone.
        assert!(
            !leaf_path.exists(),
            "leaf {} must be removed after teardown",
            leaf_path.display()
        );
    }

    /// LIVE: leak-free lifecycle. create() materializes exactly one leaf directly
    /// under the delegated base with memory.max set to the requested cap, and
    /// Drop/teardown removes it.
    #[test]
    #[ignore = "requires live cgroup v2 delegation (memory controller); run with --ignored"]
    fn live_teardown_removes_leaf_and_create_leaves_no_leak() {
        use super::CgroupLeaf;
        use super::delegated_base;
        use nono::ResourceLimits;

        let limits = ResourceLimits {
            memory_bytes: Some(64 * 1024 * 1024),
        };
        let base = delegated_base().expect("delegated base on delegated host");

        let leaf = CgroupLeaf::create(&limits).expect("create leaf");
        let leaf_path = leaf.path.clone(); // private field — in-module access
        assert!(
            leaf_path.is_dir(),
            "create() must produce a real leaf dir at {}",
            leaf_path.display()
        );
        // The leaf lives directly under the delegated base.
        assert_eq!(
            leaf_path.parent(),
            Some(base.as_path()),
            "leaf must be a child of the delegated base"
        );
        // memory.max knob actually took (controller delegated, knob written). A
        // page-multiple value is echoed back verbatim by the kernel.
        let max = std::fs::read_to_string(leaf_path.join("memory.max")).expect("read memory.max");
        assert_eq!(max.trim(), (64u64 * 1024 * 1024).to_string());

        drop(leaf); // teardown: rmdir
        assert!(
            !leaf_path.exists(),
            "teardown must remove the leaf dir {}",
            leaf_path.display()
        );
    }

    /// LIVE: a leftover leaf from a dead supervisor is swept on the next create().
    #[test]
    #[ignore = "requires live cgroup v2 delegation (memory controller); run with --ignored"]
    fn live_create_sweeps_stale_leaf_of_dead_supervisor() {
        use super::CgroupLeaf;
        use super::delegated_base;
        use nono::ResourceLimits;

        let base = delegated_base().expect("delegated base");
        // Plant a leaf named for a pid that can never be alive (above pid_max),
        // standing in for a supervisor that was SIGKILL'd before teardown.
        let stale = base.join("nono.4294967295");
        std::fs::create_dir(&stale).expect("plant stale leaf");

        // Creating our real leaf sweeps stale siblings first.
        let leaf = CgroupLeaf::create(&ResourceLimits {
            memory_bytes: Some(64 * 1024 * 1024),
        })
        .expect("create leaf");
        assert!(
            !stale.exists(),
            "a stale leaf whose supervisor is dead must be swept on create()"
        );
        drop(leaf);
    }

    /// LIVE: fail-closed against a colliding leaf. create() does fs::create_dir
    /// BEFORE arm(), and a leftover leaf with our exact pid is a hard error
    /// (no silent adoption of stale members). With the dir pre-planted, create()
    /// returns Err on EEXIST and must NOT tear down a directory it did not create.
    #[test]
    #[ignore = "requires live cgroup v2 delegation (memory controller); run with --ignored"]
    fn live_create_failure_leaves_no_partial_leaf() {
        use super::CgroupLeaf;
        use super::{delegated_base, teardown};
        use nono::ResourceLimits;

        let limits = ResourceLimits {
            memory_bytes: Some(64 * 1024 * 1024),
        };
        let base = delegated_base().expect("delegated base");
        // Plant a directory with our exact future leaf name so create()'s
        // fs::create_dir hits EEXIST and must error.
        let collide = base.join(format!("nono.{}", std::process::id()));
        std::fs::create_dir(&collide).expect("plant colliding leaf");

        let result = CgroupLeaf::create(&limits);
        assert!(
            result.is_err(),
            "create() must refuse an already-existing leaf (no silent adoption)"
        );
        // The planted directory is OURS: create() errored on EEXIST before arm(),
        // so it must not have torn down a directory it did not create.
        assert!(
            collide.is_dir(),
            "create() must not delete a pre-existing collision it did not own"
        );
        // Clean up our planted dir via the module's own teardown.
        teardown(&collide);
        assert!(!collide.exists(), "cleanup of planted leaf failed");
    }

    /// LIVE: the self-attach MECHANISM (not just pid formatting). A forked child
    /// that calls child_self_attach through the inherited cgroup.procs fd actually
    /// appears in the leaf's cgroup.procs. No bomb — the child just parks.
    #[test]
    #[ignore = "requires live cgroup v2 delegation (memory controller); run with --ignored"]
    fn live_child_self_attach_lands_pid_in_leaf_procs() {
        use super::CgroupLeaf;
        use super::child_self_attach;
        use nix::libc;
        use nix::sys::wait::waitpid;
        use nix::unistd::{ForkResult, fork};
        use nono::ResourceLimits;

        let limits = ResourceLimits {
            memory_bytes: Some(64 * 1024 * 1024),
        };
        let leaf = CgroupLeaf::create(&limits).expect("create leaf");
        let procs_fd = leaf.procs_raw_fd();
        let leaf_path = leaf.path.clone();

        // SAFETY: child uses only async-signal-safe libc calls post-fork.
        match unsafe { fork() }.expect("fork") {
            ForkResult::Child => {
                let ok = child_self_attach(procs_fd);
                if !ok {
                    unsafe { libc::_exit(126) };
                }
                // Park ~300ms so the parent can read cgroup.procs while we live.
                unsafe { libc::usleep(300_000) };
                unsafe { libc::_exit(0) };
            }
            ForkResult::Parent { child } => {
                // Give the child a beat to self-attach.
                std::thread::sleep(std::time::Duration::from_millis(50));
                let procs = std::fs::read_to_string(leaf_path.join("cgroup.procs"))
                    .expect("read leaf cgroup.procs");
                let child_pid = child.as_raw();
                let present = procs
                    .lines()
                    .filter_map(|l| l.trim().parse::<i32>().ok())
                    .any(|p| p == child_pid);
                assert!(
                    present,
                    "child pid {child_pid} must appear in leaf cgroup.procs (got {procs:?})"
                );
                let _ = waitpid(child, None);
            }
        }
        drop(leaf);
        assert!(!leaf_path.exists(), "leaf removed after teardown");
    }
}
