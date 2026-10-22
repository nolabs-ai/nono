//! Opt-in Linux namespace isolation mechanism (NEP-0004, Phase 1).
//!
//! This module is mechanism only. It applies exactly the namespace set a
//! caller supplies and never decides whether isolation should be used, which
//! network modes it may combine with, or how failures are explained to users.
//! Those decisions belong to the CLI.
//!
//! The workload runs in a new user namespace with a single-id identity
//! mapping, plus any of a new network, IPC, and UTS namespace. A new network
//! namespace contains only a loopback interface, which is brought up using the
//! `CAP_NET_ADMIN` the child holds inside its own user namespace. Optionally a
//! loopback TCP listener is created inside the new network namespace and
//! handed to the supervisor, which serves it from outside the namespace.
//!
//! Child-side operations (`NamespaceSpec::enter_raw`) use raw syscalls only and
//! never allocate, so they are safe in a `clone(2)` child of a multi-threaded
//! parent. Parent-side operations may allocate.

use super::linux::{RawSandboxError, RawSandboxStage, raw_errno};
use crate::error::{NonoError, Result};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

/// `ioctl` request returning a socket's network namespace as a new fd.
const SIOCGSKNS: libc::c_ulong = 0x894C;
/// Listen backlog for the loopback bridge listener.
const BRIDGE_BACKLOG: libc::c_int = 128;
/// Seconds the probe waits for its scratch child at each step.
const PROBE_TIMEOUT_MS: libc::c_int = 5_000;

/// Which Linux namespaces to create for the sandboxed child.
///
/// A user namespace is always created when any other namespace is requested:
/// it is what lets an unprivileged process create the others. The spec is
/// caller-supplied; this library has no default namespace set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NamespaceSpec {
    network: bool,
    ipc: bool,
    uts: bool,
    bridge_port: Option<u16>,
    loopback_tcp: bool,
}

impl NamespaceSpec {
    /// An empty spec that requests no namespaces.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Request a new network namespace containing only loopback.
    #[must_use]
    pub fn network(mut self, enabled: bool) -> Self {
        self.network = enabled;
        self
    }

    /// Request a new IPC namespace (SysV IPC and POSIX message queues).
    #[must_use]
    pub fn ipc(mut self, enabled: bool) -> Self {
        self.ipc = enabled;
        self
    }

    /// Request a new UTS namespace (hostname and domain name).
    #[must_use]
    pub fn uts(mut self, enabled: bool) -> Self {
        self.uts = enabled;
        self
    }

    /// Create a TCP listener on `127.0.0.1:port` inside the new network
    /// namespace and hand it to the parent. Requires `network(true)`.
    #[must_use]
    pub fn loopback_bridge(mut self, port: u16) -> Self {
        self.bridge_port = Some(port);
        self
    }

    /// Mark that the caller relaxes its TCP enforcement because this network
    /// namespace confines TCP to its own loopback. Requires `network(true)`.
    ///
    /// Entering the namespace is unchanged. The flag exists so the relaxation
    /// and the namespace that justifies it travel as one value: [`validate`]
    /// and [`enter_raw`] refuse it without a network namespace. Callers read
    /// [`loopback_tcp_enabled`] to pick their TCP enforcement.
    ///
    /// [`validate`]: Self::validate
    /// [`enter_raw`]: Self::enter_raw
    /// [`loopback_tcp_enabled`]: Self::loopback_tcp_enabled
    #[must_use]
    pub fn loopback_tcp(mut self, enabled: bool) -> Self {
        self.loopback_tcp = enabled;
        self
    }

    /// Whether the caller relaxes TCP enforcement inside this network
    /// namespace (see [`loopback_tcp`](Self::loopback_tcp)).
    #[must_use]
    pub fn loopback_tcp_enabled(&self) -> bool {
        self.loopback_tcp
    }

    /// Whether any namespace is requested.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.network && !self.ipc && !self.uts
    }

    /// Whether a new network namespace is requested.
    #[must_use]
    pub fn has_network(&self) -> bool {
        self.network
    }

    /// Whether a new IPC namespace is requested.
    #[must_use]
    pub fn has_ipc(&self) -> bool {
        self.ipc
    }

    /// Whether a new UTS namespace is requested.
    #[must_use]
    pub fn has_uts(&self) -> bool {
        self.uts
    }

    /// The loopback bridge port, when a bridge listener is requested.
    #[must_use]
    pub fn bridge_port(&self) -> Option<u16> {
        self.bridge_port
    }

    /// Check the spec is internally consistent.
    ///
    /// # Errors
    ///
    /// Returns an error when no namespace is requested, when a bridge or
    /// loopback TCP is requested without a network namespace, or when the
    /// bridge port is 0.
    pub fn validate(&self) -> Result<()> {
        if self.is_empty() {
            return Err(NonoError::SandboxInit(
                "namespace isolation requested with an empty namespace set".to_string(),
            ));
        }
        if self.loopback_tcp && !self.network {
            return Err(NonoError::SandboxInit(
                "loopback TCP requires a new network namespace".to_string(),
            ));
        }
        match self.bridge_port {
            Some(_) if !self.network => Err(NonoError::SandboxInit(
                "a loopback bridge requires a new network namespace".to_string(),
            )),
            Some(0) => Err(NonoError::SandboxInit(
                "the loopback bridge port must be non-zero".to_string(),
            )),
            _ => Ok(()),
        }
    }

    fn clone_flags(&self) -> libc::c_int {
        let mut flags = libc::CLONE_NEWUSER;
        if self.network {
            flags |= libc::CLONE_NEWNET;
        }
        if self.ipc {
            flags |= libc::CLONE_NEWIPC;
        }
        if self.uts {
            flags |= libc::CLONE_NEWUTS;
        }
        flags
    }

    /// Enter the requested namespaces in the calling (child) process.
    ///
    /// Unshares the namespace set, brings up loopback in a new network
    /// namespace, and creates the bridge listener if one was requested. On
    /// success returns the listener's raw fd (close-on-exec), or `None`. The
    /// parent must then write the id maps with [`write_id_maps`] before the
    /// child runs code that depends on its uid/gid.
    ///
    /// Uses raw syscalls only and never allocates. The calling process must be
    /// single-threaded and must not share its filesystem context (`CLONE_FS`).
    /// Any error is fatal to the launch: namespaces already unshared cannot be
    /// rolled back.
    ///
    /// # Errors
    ///
    /// Returns the failing stage and errno.
    pub fn enter_raw(&self) -> std::result::Result<Option<RawFd>, RawSandboxError> {
        if self.is_empty() || ((self.bridge_port.is_some() || self.loopback_tcp) && !self.network) {
            return Err(RawSandboxError::new(
                RawSandboxStage::UnshareNamespaces,
                libc::EINVAL,
            ));
        }
        // SAFETY: scalar raw syscall with no pointer arguments.
        if unsafe { libc::syscall(libc::SYS_unshare, self.clone_flags()) } < 0 {
            return Err(RawSandboxError::new(
                RawSandboxStage::UnshareNamespaces,
                raw_errno(),
            ));
        }
        if !self.network {
            return Ok(None);
        }
        loopback_up_raw()?;
        match self.bridge_port {
            Some(port) => bridge_listener_raw(port).map(Some),
            None => Ok(None),
        }
    }
}

/// Raw `struct ifreq`: 16-byte name followed by the request union. 24 bytes
/// covers the largest union member on 64-bit targets; the kernel copies
/// `sizeof(struct ifreq)`, so a larger buffer is never short.
#[repr(C)]
struct RawIfreq {
    name: [u8; 16],
    data: [u8; 24],
}

fn loopback_up_raw() -> std::result::Result<(), RawSandboxError> {
    let fail = |errno| RawSandboxError::new(RawSandboxStage::LoopbackUp, errno);
    // SAFETY: scalar raw syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_socket,
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(fail(raw_errno()));
    }
    let fd = fd as RawFd;
    let mut request = RawIfreq {
        name: [0; 16],
        data: [0; 24],
    };
    request.name[..2].copy_from_slice(b"lo");
    // SAFETY: `request` is a valid, initialized ifreq-sized stack buffer that
    // outlives both ioctls; `fd` is the socket created above.
    let result = unsafe {
        if libc::syscall(
            libc::SYS_ioctl,
            fd,
            libc::SIOCGIFFLAGS,
            &mut request as *mut RawIfreq,
        ) < 0
        {
            Err(raw_errno())
        } else {
            let flags =
                i16::from_ne_bytes([request.data[0], request.data[1]]) | libc::IFF_UP as i16;
            request.data[..2].copy_from_slice(&flags.to_ne_bytes());
            if libc::syscall(
                libc::SYS_ioctl,
                fd,
                libc::SIOCSIFFLAGS,
                &mut request as *mut RawIfreq,
            ) < 0
            {
                Err(raw_errno())
            } else {
                Ok(())
            }
        }
    };
    // SAFETY: closes the socket created above.
    unsafe {
        libc::syscall(libc::SYS_close, fd);
    }
    result.map_err(fail)
}

fn loopback_sockaddr(port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be(),
        },
        sin_zero: [0; 8],
    }
}

fn bridge_listener_raw(port: u16) -> std::result::Result<RawFd, RawSandboxError> {
    let fail = |errno| RawSandboxError::new(RawSandboxStage::BridgeListener, errno);
    // SAFETY: scalar raw syscall.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_socket,
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(fail(raw_errno()));
    }
    let fd = fd as RawFd;
    let address = loopback_sockaddr(port);
    // SAFETY: `address` is a valid sockaddr_in on the stack for the duration
    // of the call; `fd` is the socket created above.
    let ok = unsafe {
        libc::syscall(
            libc::SYS_bind,
            fd,
            &address as *const libc::sockaddr_in,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) >= 0
            && libc::syscall(libc::SYS_listen, fd, BRIDGE_BACKLOG) >= 0
    };
    if !ok {
        let errno = raw_errno();
        // SAFETY: closes the socket created above.
        unsafe {
            libc::syscall(libc::SYS_close, fd);
        }
        return Err(fail(errno));
    }
    Ok(fd)
}

/// Write a single-id identity mapping for the parent's effective uid and gid
/// into a child that has just unshared a user namespace.
///
/// Writes `setgroups` = `deny` first, as an unprivileged writer must. Called
/// by the parent (outside the namespace) while the child waits.
///
/// # Errors
///
/// Returns an error if any of the three proc files cannot be written.
pub fn write_id_maps(child: libc::pid_t) -> Result<()> {
    // SAFETY: geteuid/getegid cannot fail and take no pointers.
    let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    write_proc_file(child, "setgroups", "deny")?;
    write_proc_file(child, "uid_map", &format!("{uid} {uid} 1\n"))?;
    write_proc_file(child, "gid_map", &format!("{gid} {gid} 1\n"))
}

fn write_proc_file(child: libc::pid_t, name: &str, contents: &str) -> Result<()> {
    use std::io::Write;
    let path = format!("/proc/{child}/{name}");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .and_then(|mut file| file.write_all(contents.as_bytes()))
        .map_err(|error| {
            NonoError::SandboxInit(format!(
                "cannot write user namespace {name} for child {child}: {error}"
            ))
        })
}

/// Check that a descriptor received from a namespaced child is the loopback
/// bridge listener it should be.
///
/// The descriptor must be a close-on-exec, listening, IPv4 TCP socket bound to
/// `127.0.0.1:port`, in a network namespace other than the caller's. The last
/// check proves the bridge cannot be reached from the host network.
///
/// # Errors
///
/// Returns an error naming the first property that does not hold.
pub fn validate_bridge_listener(fd: BorrowedFd<'_>, port: u16) -> Result<()> {
    let fail = |detail: &str| NonoError::SandboxInit(format!("bridge listener: {detail}"));
    let raw = fd.as_raw_fd();
    // SAFETY: F_GETFD only reads descriptor flags.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
        return Err(fail("descriptor is not close-on-exec"));
    }
    if socket_option(raw, libc::SO_DOMAIN) != Some(libc::AF_INET)
        || socket_option(raw, libc::SO_TYPE) != Some(libc::SOCK_STREAM)
    {
        return Err(fail("descriptor is not an IPv4 TCP socket"));
    }
    if socket_option(raw, libc::SO_ACCEPTCONN) != Some(1) {
        return Err(fail("socket is not listening"));
    }
    // SAFETY: zeroed sockaddr_in is valid storage; length matches the buffer.
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    // SAFETY: pointers reference the live stack buffers above.
    let named = unsafe {
        libc::getsockname(
            raw,
            (&mut address as *mut libc::sockaddr_in).cast(),
            &mut length,
        )
    };
    let expected = loopback_sockaddr(port);
    if named < 0
        || address.sin_port != expected.sin_port
        || address.sin_addr.s_addr != expected.sin_addr.s_addr
    {
        return Err(fail("socket is not bound to the expected loopback port"));
    }
    // SAFETY: SIOCGSKNS takes no argument and returns a new fd on success.
    let netns = unsafe { libc::ioctl(raw, SIOCGSKNS as _) };
    if netns < 0 {
        return Err(fail("cannot identify the socket's network namespace"));
    }
    // SAFETY: netns is a fresh descriptor returned by the kernel.
    let netns = unsafe { OwnedFd::from_raw_fd(netns) };
    let socket_ns = std::fs::metadata(format!("/proc/self/fd/{}", netns.as_raw_fd()))
        .map_err(|_| fail("cannot inspect the socket's network namespace"))?;
    let own_ns = std::fs::metadata("/proc/self/ns/net")
        .map_err(|_| fail("cannot inspect the supervisor's network namespace"))?;
    use std::os::unix::fs::MetadataExt;
    if socket_ns.dev() == own_ns.dev() && socket_ns.ino() == own_ns.ino() {
        return Err(fail("socket is in the supervisor's network namespace"));
    }
    Ok(())
}

fn socket_option(fd: RawFd, option: libc::c_int) -> Option<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: pointers reference live stack storage of the stated length.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&mut value as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    (rc == 0).then_some(value)
}

/// Where a namespace availability probe failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NamespaceProbeStage {
    /// `unshare(2)` was refused (sysctl, seccomp, or namespace limit).
    Unshare,
    /// The parent could not write the child's uid/gid maps.
    IdMap,
    /// Loopback could not be brought up inside the new network namespace.
    /// A namespace that was created but grants no capabilities (for example
    /// under Ubuntu's AppArmor userns restriction) fails here.
    LoopbackUp,
    /// A loopback listener could not be created inside the new namespace.
    BridgeListener,
    /// The scratch child died or timed out without reporting.
    Child,
}

/// Result of [`probe_namespaces`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceProbe {
    /// The host provided every requested namespace.
    Available,
    /// The host refused the request at `stage` with `errno`.
    Unavailable {
        /// The step that failed.
        stage: NamespaceProbeStage,
        /// The errno reported by that step (0 when none applies).
        errno: i32,
    },
}

const PROBE_UNSHARED: u8 = 0x51;
const PROBE_DONE: u8 = 0x52;
const PROBE_GO: u8 = 0x53;

/// Probe whether this host can provide `spec` by attempting the real
/// operations in a scratch child process.
///
/// The probe creates the namespaces, has the parent write the id maps, brings
/// up loopback, and (when a bridge is requested) binds an ephemeral loopback
/// listener. It does not read sysctls: AppArmor, seccomp, and sysctl denials
/// all surface only when the operation is attempted.
///
/// # Errors
///
/// Returns an error if the spec is invalid or the probe itself cannot run
/// (for example, `pipe` or `clone` fails). A host refusal is reported as
/// `Ok(NamespaceProbe::Unavailable { .. })`.
pub fn probe_namespaces(spec: &NamespaceSpec) -> Result<NamespaceProbe> {
    spec.validate()?;
    // The probe's listener uses an ephemeral port; the real bridge port may
    // be in use on the host, but inside a fresh namespace it never is.
    let probe = NamespaceSpec {
        bridge_port: None,
        ..*spec
    };
    let wants_listener = spec.bridge_port.is_some();
    let (to_parent_read, to_parent_write) = pipe()?;
    let (to_child_read, to_child_write) = pipe()?;
    // SAFETY: only the address space copy is created (no CLONE_VM); the child
    // uses raw syscalls only and terminates with exit_group.
    let pid = unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD, 0, 0, 0, 0) };
    if pid < 0 {
        return Err(NonoError::SandboxInit(
            "namespace probe: clone failed".to_string(),
        ));
    }
    if pid == 0 {
        probe_child(
            &probe,
            wants_listener,
            to_parent_write.as_raw_fd(),
            to_child_read.as_raw_fd(),
        );
    }
    let pid = pid as libc::pid_t;
    drop(to_parent_write);
    drop(to_child_read);
    let outcome = probe_parent(pid, &to_parent_read, &to_child_write);
    // SAFETY: SIGKILL to our own unreaped child is harmless if it has exited.
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    loop {
        // SAFETY: waits for this exact child without a status buffer.
        let rc = unsafe { libc::waitpid(pid, std::ptr::null_mut(), 0) };
        if rc == pid || (rc < 0 && raw_errno() != libc::EINTR) {
            break;
        }
    }
    Ok(outcome)
}

fn probe_parent(pid: libc::pid_t, from_child: &OwnedFd, to_child: &OwnedFd) -> NamespaceProbe {
    let child_failed = NamespaceProbe::Unavailable {
        stage: NamespaceProbeStage::Child,
        errno: 0,
    };
    let Some(first) = read_record(from_child) else {
        return child_failed;
    };
    if first.0 != PROBE_UNSHARED {
        return decode_failure(first).unwrap_or(child_failed);
    }
    if write_id_maps(pid).is_err() {
        return NamespaceProbe::Unavailable {
            stage: NamespaceProbeStage::IdMap,
            errno: 0,
        };
    }
    // SAFETY: one-byte stack buffer on an owned pipe.
    if unsafe { libc::write(to_child.as_raw_fd(), [PROBE_GO].as_ptr().cast(), 1) } != 1 {
        return child_failed;
    }
    match read_record(from_child) {
        Some((PROBE_DONE, _)) => NamespaceProbe::Available,
        Some(record) => decode_failure(record).unwrap_or(child_failed),
        None => child_failed,
    }
}

fn decode_failure((code, errno): (u8, i32)) -> Option<NamespaceProbe> {
    let stage = match code {
        1 => NamespaceProbeStage::Unshare,
        2 => NamespaceProbeStage::LoopbackUp,
        3 => NamespaceProbeStage::BridgeListener,
        _ => return None,
    };
    Some(NamespaceProbe::Unavailable { stage, errno })
}

fn read_record(fd: &OwnedFd) -> Option<(u8, i32)> {
    let mut record = [0_u8; 5];
    let mut offset = 0;
    while offset < record.len() {
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd on the stack.
        let ready = unsafe { libc::poll(&mut poll, 1, PROBE_TIMEOUT_MS) };
        if ready < 0 && raw_errno() == libc::EINTR {
            continue;
        }
        if ready <= 0 {
            return None;
        }
        // SAFETY: offset is within the stack buffer; length is the remainder.
        let read = unsafe {
            libc::read(
                fd.as_raw_fd(),
                record[offset..].as_mut_ptr().cast(),
                record.len() - offset,
            )
        };
        if read < 0 && raw_errno() == libc::EINTR {
            continue;
        }
        if read <= 0 {
            return None;
        }
        offset += read as usize;
    }
    Some((
        record[0],
        i32::from_ne_bytes([record[1], record[2], record[3], record[4]]),
    ))
}

fn probe_child(spec: &NamespaceSpec, wants_listener: bool, report: RawFd, go: RawFd) -> ! {
    let send = |code: u8, errno: i32| {
        let mut record = [0_u8; 5];
        record[0] = code;
        record[1..].copy_from_slice(&errno.to_ne_bytes());
        // SAFETY: stack buffer on an inherited pipe end.
        unsafe {
            libc::syscall(libc::SYS_write, report, record.as_ptr(), record.len());
        }
    };
    let exit = |status: i32| -> ! {
        // SAFETY: terminates only this scratch child, without destructors.
        unsafe {
            libc::syscall(libc::SYS_exit_group, status);
            libc::_exit(status)
        }
    };
    // SAFETY: scalar raw syscall.
    if unsafe { libc::syscall(libc::SYS_unshare, spec.clone_flags()) } < 0 {
        send(1, raw_errno());
        exit(1);
    }
    send(PROBE_UNSHARED, 0);
    let mut byte = [0_u8];
    // SAFETY: one-byte stack buffer on an inherited pipe end.
    if unsafe { libc::syscall(libc::SYS_read, go, byte.as_mut_ptr(), 1) } != 1
        || byte[0] != PROBE_GO
    {
        exit(1);
    }
    if spec.network {
        if let Err(error) = loopback_up_raw() {
            send(2, error.errno());
            exit(1);
        }
        if wants_listener {
            match bridge_listener_raw(0) {
                Ok(_) => {}
                Err(error) => {
                    send(3, error.errno());
                    exit(1);
                }
            }
        }
    }
    send(PROBE_DONE, 0);
    exit(0)
}

fn pipe() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: fds is a valid two-element buffer.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(NonoError::SandboxInit(
            "namespace probe: cannot create pipe".to_string(),
        ));
    }
    // SAFETY: pipe2 succeeded and returned two fresh, owned descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_spec_is_invalid() {
        assert!(NamespaceSpec::new().validate().is_err());
    }

    #[test]
    fn bridge_requires_network() {
        let spec = NamespaceSpec::new().ipc(true).loopback_bridge(8080);
        assert!(spec.validate().is_err());
        assert!(spec.enter_raw().is_err());
    }

    #[test]
    fn loopback_tcp_requires_network() {
        let spec = NamespaceSpec::new().ipc(true).loopback_tcp(true);
        assert!(spec.validate().is_err());
        assert!(spec.enter_raw().is_err());
        let spec = NamespaceSpec::new().network(true).loopback_tcp(true);
        assert!(spec.validate().is_ok());
        assert!(spec.loopback_tcp_enabled());
    }

    #[test]
    fn bridge_port_must_be_non_zero() {
        let spec = NamespaceSpec::new().network(true).loopback_bridge(0);
        assert!(spec.validate().is_err());
    }

    #[test]
    fn clone_flags_always_include_user_namespace() {
        let spec = NamespaceSpec::new().uts(true);
        assert_eq!(spec.clone_flags(), libc::CLONE_NEWUSER | libc::CLONE_NEWUTS);
        let spec = NamespaceSpec::new().network(true).ipc(true);
        assert_eq!(
            spec.clone_flags(),
            libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWIPC
        );
    }

    #[test]
    fn probe_reports_a_definite_outcome() {
        let spec = NamespaceSpec::new()
            .network(true)
            .ipc(true)
            .uts(true)
            .loopback_bridge(18080);
        let outcome = probe_namespaces(&spec);
        assert!(outcome.is_ok(), "probe failed to run: {outcome:?}");
    }

    #[test]
    fn validate_bridge_listener_rejects_host_namespace_socket() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let fd = OwnedFd::from(listener);
        // A std listener is close-on-exec, listening, and on the right port;
        // only the namespace check can reject it. Unprivileged callers cannot
        // query a host-namespace socket at all (EPERM), which also rejects.
        let error = validate_bridge_listener(fd.as_fd(), port).expect_err("host netns");
        let message = error.to_string();
        assert!(
            message.contains("supervisor's network namespace")
                || message.contains("cannot identify the socket's network namespace"),
            "unexpected error: {message}"
        );
    }

    /// End to end: a raw-clone child sharing our fd table enters the
    /// namespaces; we validate its bridge listener and accept a connection the
    /// child makes from inside the namespace.
    #[test]
    fn bridge_listener_crosses_namespace_boundary() {
        const PORT: u16 = 18_081;
        let spec = NamespaceSpec::new().network(true).loopback_bridge(PORT);
        if probe_namespaces(&spec).expect("probe runs") != NamespaceProbe::Available {
            eprintln!("skipping: unprivileged network namespaces unavailable");
            return;
        }
        let (report_read, report_write) = pipe().expect("pipe");
        let (go_read, go_write) = pipe().expect("pipe");
        // SAFETY: CLONE_FILES shares only the fd table; the child uses raw
        // syscalls and exits without returning into the test harness.
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
        assert!(pid >= 0, "clone failed");
        if pid == 0 {
            let report = report_write.as_raw_fd();
            let go = go_read.as_raw_fd();
            let fd = match spec.enter_raw() {
                Ok(Some(fd)) => fd,
                _ => -1,
            };
            let bytes = fd.to_ne_bytes();
            // SAFETY: raw syscalls on stack buffers and inherited pipe ends.
            unsafe {
                libc::syscall(libc::SYS_write, report, bytes.as_ptr(), bytes.len());
                let mut byte = [0_u8];
                libc::syscall(libc::SYS_read, go, byte.as_mut_ptr(), 1);
                let client = libc::syscall(
                    libc::SYS_socket,
                    libc::AF_INET,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                );
                let address = loopback_sockaddr(PORT);
                let status = if client >= 0
                    && libc::syscall(
                        libc::SYS_connect,
                        client,
                        &address as *const libc::sockaddr_in,
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    ) >= 0
                    && libc::syscall(libc::SYS_write, client, b"ns".as_ptr(), 2) == 2
                {
                    0
                } else {
                    1
                };
                libc::syscall(libc::SYS_exit_group, status);
            }
        }
        let fd = read_raw_fd(&report_read);
        assert!(fd >= 3, "child failed to enter namespaces");
        // SAFETY: the child created this slot in our shared table and only
        // reports it; this test is its sole owner from here on.
        let listener = unsafe { OwnedFd::from_raw_fd(fd) };
        validate_bridge_listener(listener.as_fd(), PORT).expect("valid bridge listener");
        // SAFETY: one-byte write on an owned pipe end.
        assert_eq!(
            unsafe { libc::write(go_write.as_raw_fd(), [1_u8].as_ptr().cast(), 1) },
            1
        );
        let listener = std::net::TcpListener::from(listener);
        let (mut stream, _) = listener.accept().expect("accept bridged connection");
        let mut received = [0_u8; 2];
        std::io::Read::read_exact(&mut stream, &mut received).expect("read");
        assert_eq!(&received, b"ns");
        let mut status = 0;
        // SAFETY: waits for our own child with a valid status buffer.
        assert_eq!(
            unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) },
            pid as i32
        );
        assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
    }

    fn read_raw_fd(fd: &OwnedFd) -> RawFd {
        let mut bytes = [0_u8; 4];
        // SAFETY: four-byte stack buffer on an owned pipe end.
        let read = unsafe { libc::read(fd.as_raw_fd(), bytes.as_mut_ptr().cast(), 4) };
        if read == 4 {
            i32::from_ne_bytes(bytes)
        } else {
            -1
        }
    }

    #[test]
    fn validate_bridge_listener_rejects_wrong_port() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let fd = OwnedFd::from(listener);
        let error =
            validate_bridge_listener(fd.as_fd(), port.wrapping_add(1)).expect_err("wrong port");
        assert!(error.to_string().contains("expected loopback port"));
    }

    use std::os::fd::AsFd;
}
