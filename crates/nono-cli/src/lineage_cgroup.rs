//! Linux cgroup v2 lineage marker for tool-sandbox caller attribution.
//!
//! A daemonized caller (setsid + double-fork, reparented to pid 1) severs
//! `resolve_caller`'s parent-pid walk. Each Tool Sandbox command instead self-attaches,
//! pre-exec, to a per-command cgroup; membership survives reparenting and a
//! sandboxed command can never write `/sys/fs/cgroup` (Landlock grants none), so
//! reading a severed caller's `/proc/<pid>/cgroup` attributes it unforgeably to its
//! command. No controllers are enabled — membership only, sidestepping the EBUSY
//! no-internal-process constraint.
//!
//! No writable base -> fail closed (deny). No env-based degrade: an inherited env
//! token is forgeable via a same-uid `/proc/<pid>/environ` read.

use crate::resource_cgroup::{delegated_base, pid_is_alive, teardown as remove_cgroup};
use nix::libc;
use nono::{NonoError, Result};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::os::fd::OwnedFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const SESSION_PREFIX: &str = "nono.session.";
const CMD_PREFIX: &str = "cmd_";

/// The chosen attribution mechanism.
enum LineageKind {
    /// Writable cgroup base found; attribution is unforgeable.
    Cgroup(CgroupLineage),
    /// No writable base; severed callers are denied (fail closed).
    Disabled,
}

/// The session's lineage-attribution mechanism, built lazily on first use.
///
/// SECURITY (fail-closed): the cgroup tree is created on first attribution — never
/// eagerly at supervisor start. Building it does blocking `/sys/fs/cgroup` I/O
/// (mkdir probes, readdir), and doing that before the supervisor forks the
/// sandboxed top-level child perturbs the still-live proxy async runtime's worker
/// threads, so the fork races them and the child's Landlock exec gate can fail to
/// enforce (an unlisted command would run). First use only ever happens while
/// mediating a sub-command, which is after that fork, so the marker never touches
/// the fork's quiescence.
pub(crate) struct LineageMarker {
    supervisor_pid: u32,
    kind: OnceLock<LineageKind>,
}

impl LineageMarker {
    /// Defer the cgroup work; no filesystem I/O here. See the type's security note.
    pub(crate) fn deferred(supervisor_pid: u32) -> Self {
        Self {
            supervisor_pid,
            kind: OnceLock::new(),
        }
    }

    fn kind(&self) -> &LineageKind {
        self.kind.get_or_init(|| build_kind(self.supervisor_pid))
    }

    /// Attribute a severed caller to its command, or `None` to deny. Never the session.
    pub(crate) fn resolve_severed_command(&self, pid: u32) -> Option<String> {
        match self.kind() {
            LineageKind::Cgroup(marker) => marker.match_command(&read_process_cgroup(pid)?),
            LineageKind::Disabled => None,
        }
    }

    /// `cgroup.procs` write handle the child self-attaches through, pre-exec;
    /// `None` when disabled.
    pub(crate) fn command_procs_fd(&self, command: &str) -> Result<Option<OwnedFd>> {
        match self.kind() {
            LineageKind::Cgroup(marker) => marker.ensure_command_procs(command).map(Some),
            LineageKind::Disabled => Ok(None),
        }
    }

    /// Kill survivors in each command cgroup and remove the session tree. Idempotent.
    /// Never forces a build: nothing to tear down if the marker was never used.
    pub(crate) fn teardown(&self) {
        if let Some(LineageKind::Cgroup(marker)) = self.kind.get() {
            marker.teardown();
        }
    }

    #[cfg(test)]
    fn from_kind_for_test(kind: LineageKind) -> Self {
        let cell = OnceLock::new();
        let _ = cell.set(kind);
        Self {
            supervisor_pid: 0,
            kind: cell,
        }
    }

    /// A pre-resolved `Disabled` marker for tests that want the fail-closed path
    /// without touching a real cgroup base.
    #[cfg(test)]
    pub(crate) fn disabled_for_test() -> Self {
        Self::from_kind_for_test(LineageKind::Disabled)
    }
}

/// Choose the mechanism: writable cgroup base -> unforgeable cgroup attribution;
/// otherwise disabled (fail closed). Runs the blocking cgroup I/O, so it is only
/// ever called from `LineageMarker::kind` on first use (post-fork).
fn build_kind(supervisor_pid: u32) -> LineageKind {
    if let Some(base) = discover_writable_base() {
        match CgroupLineage::init(base, supervisor_pid) {
            Ok(marker) => return LineageKind::Cgroup(marker),
            Err(err) => tracing::warn!("cgroup lineage marker unavailable: {err}"),
        }
    } else {
        tracing::debug!("no writable cgroup v2 base for the lineage marker");
    }
    LineageKind::Disabled
}

/// A command's cgroup dir (open/teardown) plus its namespace-relative path
/// (matching `/proc/<pid>/cgroup`).
struct CommandCgroup {
    dir: PathBuf,
    rel: String,
}

pub(crate) struct CgroupLineage {
    session_dir: PathBuf,
    commands: Mutex<HashMap<String, CommandCgroup>>,
}

impl CgroupLineage {
    fn init(base: PathBuf, supervisor_pid: u32) -> Result<Self> {
        // A prior supervisor may have been SIGKILL'd before teardown; sweep its dead sessions.
        sweep_stale_sessions(&base);
        let session_dir = base.join(format!("{SESSION_PREFIX}{supervisor_pid}"));
        if let Err(err) = fs::create_dir(&session_dir)
            && err.kind() != std::io::ErrorKind::AlreadyExists
        {
            return Err(NonoError::SandboxInit(format!(
                "cgroup lineage: cannot create {}: {err}",
                session_dir.display()
            )));
        }
        Ok(Self {
            session_dir,
            commands: Mutex::new(HashMap::new()),
        })
    }

    /// Lazily create `cmd_<command>` (session-lived), then open a fresh `O_CLOEXEC`
    /// `cgroup.procs` the child self-attaches through pre-exec.
    fn ensure_command_procs(&self, command: &str) -> Result<OwnedFd> {
        if command.is_empty() || command.contains('/') {
            return Err(NonoError::SandboxInit(format!(
                "cgroup lineage: invalid command name '{command}'"
            )));
        }
        let dir = self.session_dir.join(format!("{CMD_PREFIX}{command}"));
        {
            let mut map = self.commands.lock().map_err(|_| lock_err())?;
            if !map.contains_key(command) {
                if let Err(err) = fs::create_dir(&dir)
                    && err.kind() != std::io::ErrorKind::AlreadyExists
                {
                    return Err(NonoError::SandboxInit(format!(
                        "cgroup lineage: cannot create {}: {err}",
                        dir.display()
                    )));
                }
                map.insert(
                    command.to_string(),
                    CommandCgroup {
                        rel: namespace_relative(&dir),
                        dir: dir.clone(),
                    },
                );
            }
        }
        // O_CLOEXEC is load-bearing: it must vanish at execve or the sandboxed program
        // inherits a writable cgroup.procs and could attach arbitrary same-uid pids to
        // forge lineage (Landlock gates open(), not writes on an already-open fd).
        let procs = OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(dir.join("cgroup.procs"))
            .map_err(|err| {
                NonoError::SandboxInit(format!(
                    "cgroup lineage: cannot open cgroup.procs in {}: {err}",
                    dir.display()
                ))
            })?;
        Ok(OwnedFd::from(procs))
    }

    /// Command whose cgroup contains `observed`, whole-segment matched. Lock
    /// poisoning denies.
    fn match_command(&self, observed: &str) -> Option<String> {
        let map = self.commands.lock().ok()?;
        map.iter()
            .find(|(_, cgroup)| cgroup_within(&cgroup.rel, observed))
            .map(|(name, _)| name.clone())
    }

    fn teardown(&self) {
        if let Ok(map) = self.commands.lock() {
            for cgroup in map.values() {
                remove_cgroup(&cgroup.dir);
            }
        }
        let _ = fs::remove_dir(&self.session_dir);
    }
}

fn lock_err() -> NonoError {
    NonoError::SandboxInit("cgroup lineage: command map lock poisoned".to_string())
}

/// systemd `user@<uid>.service`, else the deepest ancestor of our own cgroup leaf
/// an unprivileged mkdir can create under.
fn discover_writable_base() -> Option<PathBuf> {
    if let Ok(base) = delegated_base()
        && dir_allows_child_cgroups(&base)
    {
        return Some(base);
    }
    probe_writable_base()
}

fn probe_writable_base() -> Option<PathBuf> {
    let raw = fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = raw
        .lines()
        .find_map(|line| line.strip_prefix("0::"))?
        .trim();
    let mut leaf = PathBuf::from(CGROUP_ROOT);
    for segment in rel.split('/').filter(|s| !s.is_empty()) {
        leaf.push(segment);
    }
    let mut candidate = leaf.as_path();
    loop {
        if dir_allows_child_cgroups(candidate) {
            return Some(candidate.to_path_buf());
        }
        if candidate == Path::new(CGROUP_ROOT) {
            return None;
        }
        candidate = candidate.parent()?;
    }
}

/// The only reliable delegation test is an actual mkdir; probe with a throwaway.
fn dir_allows_child_cgroups(dir: &Path) -> bool {
    let probe = dir.join(format!("nono.lineage-probe.{}", std::process::id()));
    match fs::create_dir(&probe) {
        Ok(()) => {
            let _ = fs::remove_dir(&probe);
            true
        }
        Err(_) => false,
    }
}

/// `/proc/<pid>/cgroup` paths are namespace-relative; strip the mount prefix so
/// both sides compare in the same rooting.
fn namespace_relative(abs: &Path) -> String {
    abs.strip_prefix(CGROUP_ROOT)
        .map(|rest| format!("/{}", rest.display()))
        .unwrap_or_else(|_| abs.display().to_string())
}

/// True if `observed` is `recorded` or a descendant, whole-segment only — a
/// `starts_with` check would accept `cmd_tmuxX` for `cmd_tmux`.
fn cgroup_within(recorded: &str, observed: &str) -> bool {
    let rec: Vec<&str> = recorded.split('/').filter(|s| !s.is_empty()).collect();
    let obs: Vec<&str> = observed.split('/').filter(|s| !s.is_empty()).collect();
    !rec.is_empty() && obs.len() >= rec.len() && obs.iter().zip(&rec).all(|(a, b)| a == b)
}

fn read_process_cgroup(pid: u32) -> Option<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    raw.lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(|s| s.trim().to_string())
}

fn sweep_stale_sessions(base: &Path) {
    let Ok(entries) = fs::read_dir(base) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(parse_session_pid) else {
            continue;
        };
        if !pid_is_alive(pid) {
            teardown_session_tree(&entry.path());
        }
    }
}

fn teardown_session_tree(session_dir: &Path) {
    if let Ok(entries) = fs::read_dir(session_dir) {
        for entry in entries.flatten() {
            remove_cgroup(&entry.path());
        }
    }
    let _ = fs::remove_dir(session_dir);
}

fn parse_session_pid(name: &str) -> Option<u32> {
    name.strip_prefix(SESSION_PREFIX)?.parse::<u32>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn cgroup_with(command: &str, rel: &str) -> CgroupLineage {
        let mut map = HashMap::new();
        map.insert(
            command.to_string(),
            CommandCgroup {
                dir: PathBuf::from(format!("{CGROUP_ROOT}{rel}")),
                rel: rel.to_string(),
            },
        );
        CgroupLineage {
            session_dir: PathBuf::from("/unused"),
            commands: Mutex::new(map),
        }
    }

    #[test]
    fn cgroup_marker_attributes_severed_caller_to_its_command() {
        let marker = cgroup_with(
            "tmux",
            "/user.slice/user@1000.service/nono.session.42/cmd_tmux",
        );
        assert_eq!(
            marker.match_command("/user.slice/user@1000.service/nono.session.42/cmd_tmux"),
            Some("tmux".to_string())
        );
        // A descendant cgroup still attributes to the command.
        assert_eq!(
            marker.match_command("/user.slice/user@1000.service/nono.session.42/cmd_tmux/child"),
            Some("tmux".to_string())
        );
    }

    #[test]
    fn cgroup_marker_denies_non_matching_and_lookalike_paths() {
        let marker = cgroup_with("tmux", "/user.slice/nono.session.42/cmd_tmux");
        // Unrelated cgroup: denied.
        assert_eq!(marker.match_command("/user.slice/other.scope"), None);
        // SECURITY: whole-segment matching rejects a substring look-alike segment;
        // a `starts_with` bug would accept these and impersonate `tmux`.
        assert_eq!(
            marker.match_command("/user.slice/nono.session.42/cmd_tmuxX"),
            None
        );
        assert_eq!(
            marker.match_command("/user.slice/nono.session.42/cmd_tmux-evil"),
            None
        );
        // A prefix (an ancestor of the command cgroup) is not a member.
        assert_eq!(marker.match_command("/user.slice/nono.session.42"), None);
    }

    #[test]
    fn disabled_marker_denies_severed_caller() {
        // No writable cgroup base -> Disabled -> fail closed (deny), never a
        // command and never the session.
        assert_eq!(
            LineageMarker::disabled_for_test().resolve_severed_command(std::process::id()),
            None
        );
    }

    #[test]
    fn cgroup_within_is_whole_segment() {
        assert!(cgroup_within("/a/b", "/a/b"));
        assert!(cgroup_within("/a/b", "/a/b/c"));
        assert!(!cgroup_within("/a/b", "/a/bx"));
        assert!(!cgroup_within("/a/b", "/a"));
        assert!(!cgroup_within("/a/b", "/x/a/b"));
        // Empty recorded path never matches (guards a bug that would match all).
        assert!(!cgroup_within("", "/a/b"));
    }

    #[test]
    fn parse_session_pid_only_matches_our_sessions() {
        assert_eq!(parse_session_pid("nono.session.42"), Some(42));
        assert_eq!(parse_session_pid("nono.session.0"), Some(0));
        assert_eq!(parse_session_pid("nono.session."), None);
        assert_eq!(parse_session_pid("nono.session.abc"), None);
        assert_eq!(parse_session_pid("nono.42"), None);
        assert_eq!(parse_session_pid("cmd_tmux"), None);
    }

    #[test]
    fn namespace_relative_strips_mount_prefix() {
        assert_eq!(
            namespace_relative(Path::new(
                "/sys/fs/cgroup/user.slice/nono.session.1/cmd_tmux"
            )),
            "/user.slice/nono.session.1/cmd_tmux"
        );
    }

    /// LIVE: a sandboxed child must never write `cgroup.procs` — the property the
    /// marker's unforgeability rests on. `#[ignore]`: needs a live cgroup base +
    /// Landlock and restricts the test process itself, so run it alone.
    #[test]
    #[ignore = "requires live cgroup v2 delegation + Landlock; run with --ignored"]
    fn live_landlock_denies_child_write_to_cgroup_procs() {
        use landlock::{
            ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
            RulesetAttr, RulesetCreatedAttr, RulesetStatus,
        };

        let base = discover_writable_base().expect("a writable cgroup base");
        let marker = CgroupLineage::init(base, std::process::id()).expect("init lineage");
        let procs = marker
            .ensure_command_procs("tmux")
            .expect("open cmd cgroup.procs");
        // The supervisor (this process, outside the sandbox) can write it.
        drop(procs);
        let procs_path = marker.session_dir.join("cmd_tmux/cgroup.procs");

        let tmp = std::env::temp_dir();
        let abi = ABI::V3;
        // Restrict this process like a child: write allowed only under a temp dir,
        // nothing under /sys/fs/cgroup.
        let status = Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(abi))
            .expect("handle fs access")
            .create()
            .expect("create ruleset")
            .add_rule(PathBeneath::new(
                PathFd::new(&tmp).expect("open tmp"),
                AccessFs::from_all(abi),
            ))
            .expect("add tmp rule")
            .restrict_self()
            .expect("restrict self");

        // Landlock must actually be enforced for the denial to mean anything; on a
        // kernel without it (e.g. a minimal VM), skip rather than pass vacuously.
        if !matches!(status.ruleset, RulesetStatus::FullyEnforced) {
            eprintln!(
                "Landlock not fully enforced on this kernel ({:?}); \
                 cannot validate cgroup.procs denial",
                status.ruleset
            );
            marker.teardown();
            return;
        }

        // Now sandboxed like a child: writing the cmd cgroup.procs must be denied.
        let err = OpenOptions::new()
            .write(true)
            .open(&procs_path)
            .expect_err("sandboxed write to cgroup.procs must be denied");
        assert_eq!(
            err.raw_os_error(),
            Some(nix::libc::EACCES),
            "expected EACCES writing {}, got {err:?}",
            procs_path.display()
        );
        marker.teardown();
    }

    /// LIVE: the property the marker exists for. A daemon setsid+double-forked to
    /// pid 1 still carries its command's cgroup, so it attributes to `tmux`, never
    /// the session. `#[ignore]`: needs live cgroup v2 delegation and forks; run alone.
    #[test]
    #[ignore = "requires live cgroup v2 delegation; run with --ignored"]
    fn live_daemonized_caller_attributed_to_its_command() {
        use nix::libc;
        use nix::sys::wait::waitpid;
        use nix::unistd::{ForkResult, fork};

        let base = discover_writable_base().expect("a writable cgroup base");
        let cgroup = CgroupLineage::init(base, std::process::id()).expect("init lineage");
        let procs = cgroup
            .ensure_command_procs("tmux")
            .expect("open cmd cgroup.procs");
        let procs_fd = procs.as_raw_fd();

        // Pipe: the reparented daemon reports its own pid back to us.
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");
        let [read_fd, write_fd] = fds;

        // SAFETY: post-fork children use only async-signal-safe libc calls.
        match unsafe { fork() }.expect("fork") {
            ForkResult::Child => {
                if !crate::resource_cgroup::child_self_attach(procs_fd) {
                    unsafe { libc::_exit(126) };
                }
                // setsid + double-fork: the grandchild reparents to pid 1.
                unsafe { libc::setsid() };
                match unsafe { fork() }.expect("fork") {
                    ForkResult::Child => {
                        let pid = unsafe { libc::getpid() };
                        let bytes = pid.to_ne_bytes();
                        unsafe {
                            libc::write(write_fd, bytes.as_ptr().cast(), bytes.len());
                        }
                        // Park so the parent can read our cgroup while we live.
                        unsafe { libc::usleep(500_000) };
                        unsafe { libc::_exit(0) };
                    }
                    // Middle process exits immediately, orphaning the grandchild.
                    ForkResult::Parent { .. } => unsafe { libc::_exit(0) },
                }
            }
            ForkResult::Parent { child } => {
                unsafe { libc::close(write_fd) };
                let _ = waitpid(child, None); // reap the middle process
                let mut buf = [0u8; 4];
                let n = unsafe { libc::read(read_fd, buf.as_mut_ptr().cast(), buf.len()) };
                assert_eq!(n, 4, "expected the daemon's pid");
                unsafe { libc::close(read_fd) };
                let daemon_pid = u32::from_ne_bytes(buf);

                // Precondition: the daemon is reparented (severed ancestry).
                let ppid = parent_pid_of(daemon_pid);
                assert_eq!(ppid, Some(1), "daemon must be reparented to pid 1");

                let marker = LineageMarker::from_kind_for_test(LineageKind::Cgroup(cgroup));
                assert_eq!(
                    marker.resolve_severed_command(daemon_pid),
                    Some("tmux".to_string()),
                    "daemonized caller must attribute to its command"
                );
                // Control: this process never self-attached, so it is not a member.
                assert_eq!(marker.resolve_severed_command(std::process::id()), None);
                marker.teardown();
            }
        }
    }

    fn parent_pid_of(pid: u32) -> Option<u32> {
        let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .and_then(|rest| rest.trim().parse::<u32>().ok())
    }
}
