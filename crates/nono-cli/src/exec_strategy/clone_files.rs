//! Linux listener bootstrap. The trusted child shares only the fd table, then
//! detaches before setup/exec. No Rust allocation or locks are used in the child.
//!
//! Adapted from Luke Hinds / nolabs-ai's nono-py PR #113, specifically
//! src/sandboxed_exec.rs at 5ac03f96ed6b15c24e7833b4fb12eea08698903c:
//! https://github.com/nolabs-ai/nono-py/pull/113
//! The parent-created ruleset, combined notifications, non-reaping liveness
//! checks, and CLI integration are new. Library policy decisions remain in the
//! CLI; library preparation only applies the capabilities supplied here.

use super::ExecConfig;
use crate::profile::LinuxSandboxPolicy;
use nix::libc;
use nono::sandbox::{self, PreparedLandlockSandbox, PreparedSeccompNotifyFilter};
use nono::{CapabilitySet, DetectedAbi, NonoError, Result};
use std::collections::BTreeSet;
use std::ffi::CStr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, MutexGuard};

const READY: u8 = 0xc1;
const DETACHED: u8 = 0xd1;
const ACK: u8 = 0xa1;
const BOOTSTRAP_SECONDS: i64 = 15;

// All supervised notification sessions hold this lock until their listener
// owners have been dropped. Thus no listener can appear/disappear in this fd
// table during another shared bootstrap's discovery of an unreported listener.
// Ordinary proxy-thread fd churn does not acquire this lock and is supported.
static LISTENER_OWNERSHIP: Mutex<()> = Mutex::new(());

pub(super) fn lock_listener_ownership() -> Result<MutexGuard<'static, ()>> {
    LISTENER_OWNERSHIP
        .lock()
        .map_err(|_| failure("listener ownership lock poisoned"))
}

pub(super) struct Bootstrap {
    pub child: nix::unistd::Pid,
    pub network: Option<OwnedFd>,
}

pub(super) struct Command<'a> {
    pub program: &'a CStr,
    pub argv: &'a [*const libc::c_char],
    pub envp: &'a [*const libc::c_char],
    pub cwd: &'a CStr,
    pub supervisor_fd: Option<RawFd>,
    pub pty_slave: Option<RawFd>,
    pub resource_procs: Option<RawFd>,
    #[cfg(test)]
    pub fault: Fault,
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum Fault {
    #[default]
    None,
    LateFd,
    PendingSignal,
    BeforeListener,
    AfterFilesystem,
    AfterListener,
    BeforeDetach,
    AfterDetach,
    InvalidReport,
    FailedAck,
    BadAck,
    AfterAck,
    Fragmented,
}

fn failure(detail: &str) -> NonoError {
    NonoError::SandboxInit(format!("CLONE_FILES bootstrap: {detail}"))
}

fn prepare(
    caps: &CapabilitySet,
    abi: &DetectedAbi,
    policy: LinuxSandboxPolicy,
) -> Result<PreparedLandlockSandbox> {
    match policy {
        LinuxSandboxPolicy::Auto => {
            sandbox::prepare_seccomp_with_abi(caps, abi, nono::SeccompOpts::network_baseline())
        }
        LinuxSandboxPolicy::External => {
            sandbox::prepare_seccomp_with_abi(caps, abi, nono::SeccompOpts::external_tcp())
        }
        LinuxSandboxPolicy::Landlock => sandbox::prepare_landlock_with_abi(caps, abi),
    }
}

fn above_stdio(fd: OwnedFd) -> Result<OwnedFd> {
    if fd.as_raw_fd() >= 3 {
        return Ok(fd);
    }
    // SAFETY: fd is owned, and F_DUPFD_CLOEXEC returns a fresh descriptor.
    let duplicate = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(failure("cannot move bootstrap endpoint above stdio"));
    }
    // SAFETY: duplicate was checked and is uniquely owned.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

pub(super) fn promote_supervisor_socket(
    socket: nono::SupervisorSocket,
) -> Result<nono::SupervisorSocket> {
    if socket.as_raw_fd() >= 3 {
        return Ok(socket);
    }
    // SAFETY: retain the original owner until a fresh duplicate is acquired.
    let fd = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(failure("cannot move supervisor socket above stdio"));
    }
    // SAFETY: checked fresh descriptor, now owned by the new socket wrapper.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(nono::SupervisorSocket::from_stream(UnixStream::from(fd)))
}

// Occupy otherwise closed stdio slots so NEW_LISTENER cannot return an fd
// later confused with stdio. O_PATH keeps reads/writes failing as for closed
// stdio. These owned placeholders are never installed over an occupied slot.
fn reserve_stdio() -> Result<Vec<OwnedFd>> {
    let mut reserved = Vec::new();
    loop {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open("/dev/null")
            .map_err(NonoError::Io)?;
        if file.as_raw_fd() >= 3 {
            break;
        }
        reserved.push(file.into());
    }
    Ok(reserved)
}

/// The caller holds LISTENER_OWNERSHIP through destruction of returned listeners.
pub(super) fn spawn(
    config: &ExecConfig<'_>,
    command: Command<'_>,
    caps: &CapabilitySet,
    abi: DetectedAbi,
) -> Result<Bootstrap> {
    if sandbox::is_wsl2() {
        return Err(failure("required notification filters unavailable on WSL2"));
    }
    let baseline = prepare(caps, &abi, config.sandbox_policy)?;
    let network = if config.seccomp_policy.proxy_fallback {
        let has_bind = matches!(caps.network_mode(), nono::NetworkMode::ProxyOnly { bind_ports, .. } if !bind_ports.is_empty());
        sandbox::prepare_seccomp_proxy_filter(has_bind)
    } else {
        sandbox::prepare_seccomp_af_unix_filter()
    };
    let network = if config.seccomp_policy.needs_openat_notify() {
        network.with_openat_notifications()
    } else {
        network
    };
    let gate = config
        .tool_sandbox_runtime
        .map(|runtime| runtime.prepare_outer_exec_gate())
        .transpose()?
        .map(above_stdio)
        .transpose()?;
    let (parent, child) =
        UnixStream::pair().map_err(|_| failure("cannot create bootstrap socketpair"))?;
    let parent = above_stdio(parent.into())?;
    let child = above_stdio(child.into())?;
    let closed_stdio = reserve_stdio()?;
    let snapshot = listeners()?;
    let mut signals = Signals::block()?;
    // SAFETY: getpid takes no pointers and cannot fail.
    let parent_pid = unsafe { libc::getpid() };
    // SAFETY: only the fd table is shared. VM, TLS, signal handlers and FS
    // context are copied. The child never returns into allocating Rust code.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone,
            libc::CLONE_FILES | libc::SIGCHLD,
            0,
            0,
            0,
            0,
        )
    };
    if pid == 0 {
        arm_allocator_guard();
        child_exec(
            &command,
            &baseline,
            &network,
            gate.as_ref().map(AsRawFd::as_raw_fd),
            child.as_raw_fd(),
            parent.as_raw_fd(),
            parent_pid,
            &signals,
            &closed_stdio,
        );
    }
    if pid < 0 {
        return Err(failure("clone failed"));
    }
    let pid = pid as libc::pid_t;

    // Everything with a descriptor the child will use stays alive until the
    // handshake returns DETACHED or cleanup has killed AND reaped the child.
    let mut ruleset = None;
    let mut cleanup_dir = None;
    #[cfg(test)]
    let mut late_fd = None;
    let handshake = (|| -> Result<RawFd> {
        // Harden before releasing the child, and before any untrusted code can
        // exec. The child independently enables inspection for notifications.
        // SAFETY: prctl changes only the parent's dumpability.
        if unsafe { libc::syscall(libc::SYS_prctl, libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } < 0 {
            return Err(failure("cannot harden parent"));
        }
        signals.restore()?;
        let mut ready = [0_u8];
        if !transfer(parent.as_raw_fd(), &mut ready, false, Some(pid)) || ready[0] != READY {
            return Err(failure("child failed before preparation"));
        }
        #[cfg(test)]
        if command.fault == Fault::LateFd {
            // SAFETY: owned endpoint duplicated after the original fd snapshot.
            let fd = unsafe { libc::fcntl(parent.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 512) };
            if fd < 0 {
                return Err(failure("test cannot allocate late high fd"));
            }
            // SAFETY: checked fresh owned descriptor, retained through detach.
            late_fd = Some(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        let mut child_caps = caps.clone();
        child_caps.remap_procfs_self_references(pid as u32, None);
        child_caps.widen_procfs_self_to_proc();
        let prepared = prepare(&child_caps, &abi, config.sandbox_policy)?;
        ruleset = Some(above_stdio(prepared.create_ruleset()?)?);
        let Some(ref ruleset) = ruleset else {
            return Err(failure("missing ruleset"));
        };
        cleanup_dir = Some(above_stdio(
            std::fs::File::open(format!("/proc/{pid}/fd"))
                .map_err(|_| failure("cannot open child descriptor directory"))?
                .into(),
        )?);
        let Some(ref cleanup_dir) = cleanup_dir else {
            return Err(failure("missing descriptor directory"));
        };
        let mut bytes = [0_u8; 8];
        bytes[..4].copy_from_slice(&ruleset.as_raw_fd().to_ne_bytes());
        bytes[4..].copy_from_slice(&cleanup_dir.as_raw_fd().to_ne_bytes());
        if !transfer(parent.as_raw_fd(), &mut bytes, true, Some(pid)) {
            return Err(failure("cannot send prepared ruleset"));
        }
        let mut report = [0_u8; 5];
        if !transfer(parent.as_raw_fd(), &mut report, false, Some(pid)) {
            return Err(failure("child died or timed out before DETACHED"));
        }
        if report[4] != DETACHED {
            return Err(failure("invalid detachment confirmation"));
        }
        let network_fd = i32::from_ne_bytes([report[0], report[1], report[2], report[3]]);
        validate_listener(network_fd, &snapshot)?;
        let expected: BTreeSet<_> = [network_fd].into_iter().collect();
        let actual: BTreeSet<_> = listeners()?.difference(&snapshot).copied().collect();
        if actual != expected {
            return Err(failure("listener ownership mismatch"));
        }
        // Use send(MSG_NOSIGNAL) only in the parent; the child's filter traps it.
        #[cfg(test)]
        if command.fault == Fault::FailedAck {
            // SAFETY: fault injection affects only this owned endpoint.
            unsafe {
                libc::shutdown(parent.as_raw_fd(), libc::SHUT_WR);
            }
        }
        let ack = ACK;
        #[cfg(test)]
        let ack = if command.fault == Fault::BadAck {
            0
        } else {
            ack
        };
        if !transfer(parent.as_raw_fd(), &mut [ack], true, Some(pid)) {
            return Err(failure("acknowledgment failed"));
        }
        Ok(network_fd)
    })();
    let network_fd = match handshake {
        Ok(fds) => fds,
        Err(error) => {
            kill_and_reap(pid);
            cleanup_listeners(&snapshot);
            return Err(error);
        }
    };
    // SAFETY: DETACHED was received, identity/ownership checked, and this is
    // the only parent owner. The child closes its private copies before exec.
    let network = Some(unsafe { OwnedFd::from_raw_fd(network_fd) });
    Ok(Bootstrap {
        child: nix::unistd::Pid::from_raw(pid),
        network,
    })
}

#[allow(clippy::too_many_arguments)]
fn child_exec(
    command: &Command<'_>,
    baseline: &PreparedLandlockSandbox,
    network: &PreparedSeccompNotifyFilter,
    gate: Option<RawFd>,
    socket: RawFd,
    parent_socket: RawFd,
    parent_pid: libc::pid_t,
    signals: &Signals,
    closed_stdio: &[OwnedFd],
) -> ! {
    // SAFETY: raw scalar syscalls, no libc process/thread coordination.
    if unsafe {
        libc::syscall(
            libc::SYS_prctl,
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL,
            0,
            0,
            0,
        )
    } < 0
        || unsafe { libc::syscall(libc::SYS_getppid) } != parent_pid as libc::c_long
    {
        die(126);
    }
    // SAFETY: runtime mediation reads this child's memory through procfs. This
    // is set explicitly rather than depending on the parent's inherited value.
    if unsafe { libc::syscall(libc::SYS_prctl, libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } < 0 {
        die(126);
    }
    if !transfer(socket, &mut [READY], true, None) {
        die(126);
    }
    #[cfg(test)]
    if command.fault == Fault::PendingSignal {
        // SAFETY: queue a signal to ourselves while all catchable signals are blocked.
        unsafe {
            libc::syscall(
                libc::SYS_kill,
                libc::syscall(libc::SYS_getpid),
                libc::SIGUSR1,
            );
        }
    }
    let mut bytes = [0_u8; 8];
    if !transfer(socket, &mut bytes, false, None) {
        die(126);
    }
    let ruleset = i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let cleanup_dir = i32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if ruleset < 3 || cleanup_dir < 3 || ruleset == cleanup_dir {
        die(126);
    }
    #[cfg(test)]
    if command.fault == Fault::BeforeListener {
        die(126);
    }
    let network_fd = match network.install_raw() {
        Ok(fd) => fd,
        Err(_) => die(126),
    };
    #[cfg(test)]
    if matches!(
        command.fault,
        Fault::AfterFilesystem | Fault::AfterListener | Fault::BeforeDetach
    ) {
        die(126);
    }
    // Empty close_range unshares without closing anything. On older kernels,
    // unshare(CLONE_FILES) has the same table-isolation property.
    // SAFETY: scalar syscall arguments; no fd cleanup before success.
    let detached = unsafe { libc::syscall(libc::SYS_close_range, u32::MAX, u32::MAX, 2_u32) };
    if detached < 0 {
        // SAFETY: shares no memory or FS state; only detaches the fd table.
        if unsafe { libc::syscall(libc::SYS_unshare, libc::CLONE_FILES) } < 0 {
            die(126);
        }
    }
    #[cfg(test)]
    if command.fault == Fault::AfterDetach {
        die(126);
    }
    let mut report = [0_u8; 5];
    report[..4].copy_from_slice(&network_fd.to_ne_bytes());
    report[4] = DETACHED;
    #[cfg(test)]
    if command.fault == Fault::InvalidReport {
        report[..4].copy_from_slice(&command.supervisor_fd.unwrap_or(1).to_ne_bytes());
    }
    #[cfg(test)]
    let sent = if command.fault == Fault::Fragmented {
        report
            .iter_mut()
            .all(|byte| transfer(socket, std::slice::from_mut(byte), true, None))
    } else {
        transfer(socket, &mut report, true, None)
    };
    #[cfg(not(test))]
    let sent = transfer(socket, &mut report, true, None);
    if !sent {
        die(126);
    }
    let mut ack = [0_u8];
    if !transfer(socket, &mut ack, false, None) || ack[0] != ACK {
        die(126);
    }
    #[cfg(test)]
    if command.fault == Fault::AfterAck {
        die(126);
    }
    // SAFETY: confirmed private table, owned bootstrap endpoints.
    unsafe {
        libc::syscall(libc::SYS_close, socket);
        libc::syscall(libc::SYS_close, parent_socket);
    }
    for fd in closed_stdio {
        // SAFETY: these are owned placeholders in the now-private table.
        unsafe {
            libc::syscall(libc::SYS_close, fd.as_raw_fd());
        }
    }
    if let Some(fd) = command.resource_procs
        && !attach_resource_cgroup(fd)
    {
        die(126);
    }
    if let Some(fd) = command.pty_slave
        && !setup_pty(fd)
    {
        die(126);
    }
    if gate.is_some() {
        // SAFETY: cwd is a prebuilt NUL-terminated string, live through exec.
        if unsafe { libc::syscall(libc::SYS_chdir, command.cwd.as_ptr()) } < 0 {
            die(126);
        }
    }
    // SAFETY: only scalar arguments and checked shared ruleset/gate fds. These
    // kernel objects were fully populated in the parent before its release.
    unsafe {
        if libc::syscall(libc::SYS_prctl, libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
            die(126);
        }
        if let Some(fd) = gate
            && libc::syscall(libc::SYS_landlock_restrict_self, fd, 0_u32) < 0
        {
            die(126);
        }
        if libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0_u32) < 0 {
            die(126);
        }
    }
    if baseline.apply_static_network_raw().is_err() {
        die(126);
    }
    if gate.is_none() {
        // SAFETY: cwd remains live. Matches the existing post-sandbox chdir.
        if unsafe { libc::syscall(libc::SYS_chdir, command.cwd.as_ptr()) } < 0 {
            die(126);
        }
    }
    if !scrub_fds(cleanup_dir, command.supervisor_fd) {
        die(126);
    }
    if let Some(fd) = command.supervisor_fd {
        // SAFETY: the sole intentionally inherited non-stdio descriptor.
        if unsafe { libc::syscall(libc::SYS_fcntl, fd, libc::F_SETFD, 0) } < 0 {
            die(126);
        }
    }
    if !signals.restore_child() {
        die(126);
    }
    // SAFETY: all strings/pointer arrays were prepared in the parent and have
    // remained live in the child's private VM. No Rust unwinding on failure.
    unsafe {
        libc::syscall(
            libc::SYS_execve,
            command.program.as_ptr(),
            command.argv.as_ptr(),
            command.envp.as_ptr(),
        );
    }
    die(127)
}

fn attach_resource_cgroup(fd: RawFd) -> bool {
    // SAFETY: getpid is a scalar raw syscall.
    let pid = unsafe { libc::syscall(libc::SYS_getpid) } as libc::pid_t;
    let mut storage = itoa::Buffer::new();
    let bytes = storage.format(pid).as_bytes();
    loop {
        // SAFETY: stack buffer and the caller's inherited cgroup.procs fd.
        let written = unsafe { libc::syscall(libc::SYS_write, fd, bytes.as_ptr(), bytes.len()) };
        if written < 0 && errno() == libc::EINTR {
            continue;
        }
        return written == bytes.len() as libc::c_long;
    }
}

fn setup_pty(slave: RawFd) -> bool {
    // SAFETY: called only with a private table and valid inherited PTY slave.
    unsafe {
        if libc::syscall(libc::SYS_setsid) < 0
            || libc::syscall(libc::SYS_ioctl, slave, libc::TIOCSCTTY, 0) < 0
        {
            return false;
        }
        for target in 0..=2 {
            if slave == target {
                if libc::syscall(libc::SYS_fcntl, slave, libc::F_SETFD, 0) < 0 {
                    return false;
                }
            } else if libc::syscall(libc::SYS_dup3, slave, target, 0) < 0 {
                return false;
            }
        }
        if slave > 2 && libc::syscall(libc::SYS_close, slave) < 0 {
            return false;
        }
    }
    true
}

/// Enumerate the child's live table, not the parent's startup snapshot. The
/// directory was opened by the parent using /proc/CHILD/fd before openat was
/// trapped. It continues to refer to the child after the table detaches.
fn scrub_fds(directory: RawFd, keep: Option<RawFd>) -> bool {
    let mut buffer = [0_u8; 4096];
    loop {
        // SAFETY: initialized stack buffer, private descriptor table. Linux's
        // proc fd directory position is the fd number, so closing earlier
        // entries does not skip or renumber later entries.
        let count = unsafe {
            libc::syscall(
                libc::SYS_getdents64,
                directory,
                buffer.as_mut_ptr(),
                buffer.len(),
            )
        };
        if count < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return false;
        }
        if count == 0 {
            break;
        }
        let count = count as usize;
        if count > buffer.len() {
            return false;
        }
        let mut offset = 0_usize;
        while offset < count {
            // linux_dirent64: ino(8), offset(8), reclen(2), type(1), name.
            if count - offset < 20 {
                return false;
            }
            let length = u16::from_ne_bytes([buffer[offset + 16], buffer[offset + 17]]) as usize;
            if length < 20 || length > count - offset {
                return false;
            }
            let name = &buffer[offset + 19..offset + length];
            let mut number = Some(0_i32);
            let mut terminated = false;
            for byte in name {
                if *byte == 0 {
                    terminated = true;
                    break;
                }
                if !byte.is_ascii_digit() {
                    number = None;
                }
                number = number
                    .and_then(|n| n.checked_mul(10))
                    .and_then(|n| n.checked_add(i32::from(*byte) - i32::from(b'0')));
            }
            if !terminated {
                return false;
            }
            if let Some(fd) = number
                && fd >= 3
                && fd != directory
                && Some(fd) != keep
            {
                // SAFETY: this entry belongs to our private table, and no
                // thread or signal handler can create/reuse slots here.
                let closed = unsafe { libc::syscall(libc::SYS_close, fd) };
                if closed < 0 && errno() != libc::EINTR {
                    return false;
                }
            }
            offset += length;
        }
    }
    // SAFETY: directory is no longer needed, and is not an inherited endpoint.
    unsafe { libc::syscall(libc::SYS_close, directory) >= 0 }
}

fn listener_target(target: &std::path::Path) -> bool {
    target == std::path::Path::new("anon_inode:seccomp notify")
        || target == std::path::Path::new("anon_inode:[seccomp notify]")
}

fn listeners() -> Result<BTreeSet<RawFd>> {
    let mut result = BTreeSet::new();
    for entry in std::fs::read_dir("/proc/self/fd")
        .map_err(|_| failure("cannot enumerate listener owners"))?
    {
        let entry = entry.map_err(|_| failure("cannot enumerate descriptor"))?;
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<RawFd>() else {
            continue;
        };
        match std::fs::read_link(entry.path()) {
            Ok(target) if listener_target(&target) => {
                result.insert(fd);
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // ordinary fd churn
            Err(_) => return Err(failure("cannot inspect descriptor identity")),
        }
    }
    Ok(result)
}

fn validate_listener(fd: RawFd, snapshot: &BTreeSet<RawFd>) -> Result<()> {
    if fd < 3 || snapshot.contains(&fd) {
        return Err(failure("invalid or pre-existing listener slot"));
    }
    let target = std::fs::read_link(format!("/proc/self/fd/{fd}"))
        .map_err(|_| failure("listener disappeared"))?;
    // SAFETY: F_GETFD does not mutate the descriptor table.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if !listener_target(&target) || flags < 0 || flags & libc::FD_CLOEXEC == 0 {
        return Err(failure(
            "reported descriptor is not a close-on-exec listener",
        ));
    }
    Ok(())
}

fn cleanup_listeners(snapshot: &BTreeSet<RawFd>) {
    let current = match listeners() {
        Ok(current) => current,
        // Cannot prove which descriptors were created. The only fail-closed
        // cleanup is to terminate this CLI process and release its entire table.
        Err(_) => std::process::exit(126),
    };
    for fd in current.difference(snapshot) {
        // SAFETY: child reaped; session ownership lock excludes other listener
        // creators/destructors. Never close an unvalidated reported raw number.
        unsafe {
            libc::close(*fd);
        }
    }
}

fn kill_and_reap(pid: libc::pid_t) {
    // SAFETY: bootstrap probes use WNOWAIT, so this PID has not been reaped
    // and cannot be reused. It is our direct, trusted child.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    loop {
        // SAFETY: waits for that exact child, without a status buffer.
        let result = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        if result == pid || (result < 0 && errno() == libc::ECHILD) {
            return;
        }
        if result < 0 && errno() != libc::EINTR {
            std::process::exit(126);
        }
    }
}

fn errno() -> i32 {
    // SAFETY: inherited TLS is private; errno access does not allocate or lock.
    unsafe { *libc::__errno_location() }
}

fn monotonic_seconds() -> Option<i64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid stack buffer, raw syscall avoids vDSO/libc initialization.
    if unsafe { libc::syscall(libc::SYS_clock_gettime, libc::CLOCK_MONOTONIC, &mut time) } < 0 {
        None
    } else {
        Some(time.tv_sec)
    }
}

/// Raw, bounded exact I/O. In the parent, additionally detect child death
/// without reaping it; socket EOF cannot be relied on in the shared table.
fn transfer(fd: RawFd, bytes: &mut [u8], write: bool, child: Option<libc::pid_t>) -> bool {
    let Some(start) = monotonic_seconds() else {
        return false;
    };
    let deadline = start.saturating_add(BOOTSTRAP_SECONDS);
    let mut offset = 0;
    while offset < bytes.len() {
        if monotonic_seconds().is_none_or(|now| now >= deadline) {
            return false;
        }
        if let Some(pid) = child {
            // SAFETY: zeroed siginfo is valid storage for waitid; WNOWAIT
            // preserves our ability to signal and reap this exact child.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if rc < 0 {
                if errno() == libc::EINTR {
                    continue;
                }
                return false;
            }
            // SAFETY: waitid initializes the child identity member.
            if unsafe { info.si_pid() } == pid {
                return false;
            }
        }
        let mut poll = libc::pollfd {
            fd,
            events: if write { libc::POLLOUT } else { libc::POLLIN },
            revents: 0,
        };
        // SAFETY: one initialized pollfd; bounded wait keeps liveness checked.
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 20_000_000,
        };
        let rc = unsafe {
            libc::syscall(
                libc::SYS_ppoll,
                &mut poll,
                1_usize,
                &timeout,
                std::ptr::null::<u64>(),
                8_usize,
            )
        };
        if rc < 0 {
            if errno() == libc::EINTR {
                continue;
            }
            return false;
        }
        if rc == 0 {
            continue;
        }
        if poll.revents & poll.events == 0 {
            return false;
        }
        // SAFETY: offset is bounded by bytes.len(); transfer length cannot
        // exceed the remaining initialized buffer. Parent send avoids SIGPIPE.
        let rc = unsafe {
            if write && child.is_some() {
                libc::send(
                    fd,
                    bytes[offset..].as_ptr().cast(),
                    bytes.len() - offset,
                    libc::MSG_NOSIGNAL,
                )
            } else if write {
                libc::syscall(
                    libc::SYS_write,
                    fd,
                    bytes[offset..].as_ptr(),
                    bytes.len() - offset,
                ) as isize
            } else {
                libc::syscall(
                    libc::SYS_read,
                    fd,
                    bytes[offset..].as_mut_ptr(),
                    bytes.len() - offset,
                ) as isize
            }
        };
        if rc < 0 && (errno() == libc::EINTR || errno() == libc::EAGAIN) {
            continue;
        }
        if rc <= 0 {
            return false;
        }
        offset += rc as usize;
    }
    true
}

struct Signals {
    old: u64,
    ignored: [bool; 65],
    restored: bool,
}
impl Signals {
    fn block() -> Result<Self> {
        let mut result = Self {
            old: 0,
            ignored: [false; 65],
            restored: false,
        };
        let all = u64::MAX;
        // SAFETY: the Linux kernel signal mask is 64 bits (unlike libc's padded
        // sigset_t). Block runtime-private signals too in the raw clone child.
        if unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                &all,
                &mut result.old,
                8_usize,
            )
        } < 0
        {
            result.restored = true;
            return Err(failure("cannot block bootstrap signals"));
        }
        for signal in 1..=64 {
            if signal == libc::SIGKILL || signal == libc::SIGSTOP {
                continue;
            }
            let mut action = [0_usize; 4];
            // SAFETY: oversized kernel sigaction buffer on supported Linux
            // architectures; handler is its first word. No libc reserved-signal
            // filtering, so runtime-private handlers are captured too.
            if unsafe {
                libc::syscall(
                    libc::SYS_rt_sigaction,
                    signal,
                    std::ptr::null::<usize>(),
                    action.as_mut_ptr(),
                    8_usize,
                )
            } < 0
            {
                return Err(failure("cannot capture signal disposition"));
            }
            result.ignored[signal as usize] = action[0] == libc::SIG_IGN;
        }
        Ok(result)
    }
    fn restore(&mut self) -> Result<()> {
        if self.restored {
            return Ok(());
        }
        // SAFETY: old was initialized by rt_sigprocmask for this thread.
        if unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                &self.old,
                std::ptr::null_mut::<u64>(),
                8_usize,
            )
        } < 0
        {
            return Err(failure("cannot restore parent signal mask"));
        }
        self.restored = true;
        Ok(())
    }
    fn restore_child(&self) -> bool {
        for signal in 1..=64 {
            if signal == libc::SIGKILL || signal == libc::SIGSTOP {
                continue;
            }
            // For a default/ignored action flags, restorer and mask are all
            // zero, independent of architecture-specific sigaction layout.
            let action = [
                if self.ignored[signal as usize] {
                    libc::SIG_IGN
                } else {
                    libc::SIG_DFL
                },
                0,
                0,
                0,
            ];
            // SAFETY: fixed kernel action, no user handler can run before exec.
            if unsafe {
                libc::syscall(
                    libc::SYS_rt_sigaction,
                    signal,
                    action.as_ptr(),
                    std::ptr::null_mut::<usize>(),
                    8_usize,
                )
            } < 0
            {
                return false;
            }
        }
        // SAFETY: restore only after replacing inherited runtime handlers.
        unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                &self.old,
                std::ptr::null_mut::<u64>(),
                8_usize,
            ) >= 0
        }
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        if self.restore().is_err() {
            std::process::exit(126);
        }
    }
}

fn die(status: i32) -> ! {
    // SAFETY: no destructors, allocation, locks, or potentially blocking error
    // writes. exit_group terminates the copied process, never the parent.
    unsafe {
        libc::syscall(libc::SYS_exit_group, status);
        libc::_exit(status);
    }
}

#[cfg(debug_assertions)]
mod allocation_guard {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::atomic::{AtomicBool, Ordering};
    pub(super) static ARMED: AtomicBool = AtomicBool::new(false);
    struct Guarded;
    #[global_allocator]
    static ALLOCATOR: Guarded = Guarded;
    fn check() {
        if ARMED.load(Ordering::Relaxed) {
            super::die(125);
        }
    }
    // SAFETY: delegates the GlobalAlloc contract to System, unless the private
    // raw-clone child flag forbids all allocator activity, including deallocation.
    unsafe impl GlobalAlloc for Guarded {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            check();
            // SAFETY: forwarded unchanged from GlobalAlloc's caller.
            unsafe { System.alloc(layout) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            check();
            // SAFETY: forwarded unchanged from GlobalAlloc's caller.
            unsafe { System.alloc_zeroed(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            check();
            // SAFETY: forwarded unchanged from GlobalAlloc's caller.
            unsafe {
                System.dealloc(ptr, layout);
            }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            check();
            // SAFETY: forwarded unchanged from GlobalAlloc's caller.
            unsafe { System.realloc(ptr, layout, size) }
        }
    }
}
fn arm_allocator_guard() {
    #[cfg(debug_assertions)]
    allocation_guard::ARMED.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[cfg(test)]
mod tests;
