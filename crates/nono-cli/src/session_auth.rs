//! Authentication for session-owned named sockets. Anonymous inherited sockets
//! are capabilities and must not use this check: their peer predates fork.

use nix::libc;
use nono::supervisor::socket::peer_credentials;
use nono::{NonoError, Result};
use std::os::fd::RawFd;

#[cfg(target_os = "macos")]
mod macos;

const MAX_ANCESTRY: usize = 128;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Process {
    pid: u32,
    parent: u32,
    birth: (u64, u64),
}

/// Every ordinary child and brokered tool descends from this supervisor.
/// `owns_orphan` may additionally establish membership using protected lineage.
pub(crate) fn authenticate(
    socket: RawFd,
    enabled: bool,
    owns_orphan: impl FnOnce(u32) -> bool,
) -> Result<u32> {
    let peer = peer_credentials(socket)?;
    if !enabled {
        return Ok(peer.pid);
    }
    // SAFETY: getuid has no preconditions.
    if peer.uid != unsafe { libc::getuid() } || peer.pid == 0 {
        return Err(denied());
    }
    let lifetime = PeerLifetime::new(socket)?;
    let process = inspect(peer.pid)?;
    verify_membership(process, std::process::id(), owns_orphan, inspect)?;
    #[cfg(target_os = "macos")]
    macos::verify_ownership(socket, peer.pid)?;
    lifetime.verify(socket)?;
    if inspect(peer.pid)?.birth != process.birth || peer_credentials(socket)?.pid != peer.pid {
        return Err(denied());
    }
    Ok(peer.pid)
}

pub(crate) fn validate_support(enabled: bool) -> Result<()> {
    if enabled {
        use std::os::fd::AsRawFd;
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().map_err(|err| {
            NonoError::SandboxInit(format!("cannot probe session socket authentication: {err}"))
        })?;
        PeerLifetime::new(socket.as_raw_fd())?;
        #[cfg(target_os = "macos")]
        macos::verify_ownership(socket.as_raw_fd(), std::process::id())?;
    }
    Ok(())
}

fn denied() -> NonoError {
    NonoError::SandboxInit("socket caller does not belong to this nono session".to_string())
}

fn socket_option<const N: usize>(socket: RawFd, level: i32, option: i32) -> Result<[u32; N]> {
    let mut value = [0; N];
    let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: value is an initialized buffer of size bytes; integer arrays accept
    // every bit pattern. The returned size is checked before using the value.
    let ret =
        unsafe { libc::getsockopt(socket, level, option, value.as_mut_ptr().cast(), &mut size) };
    if ret != 0 {
        return Err(NonoError::SandboxInit(format!(
            "cannot authenticate socket peer: {}",
            std::io::Error::last_os_error()
        )));
    }
    if size as usize != std::mem::size_of_val(&value) {
        return Err(denied());
    }
    Ok(value)
}

fn verify_membership(
    process: Process,
    root: u32,
    owns_orphan: impl FnOnce(u32) -> bool,
    inspect: impl FnMut(u32) -> Result<Process>,
) -> Result<()> {
    // An ancestor may exit during the walk. Protected lineage is independent
    // proof of membership, including when ancestry could not be inspected.
    // The caller must still pass the lifetime and identity checks afterwards.
    if walk_ancestry(process, root, inspect).unwrap_or(false) || owns_orphan(process.pid) {
        Ok(())
    } else {
        Err(denied())
    }
}

fn walk_ancestry(
    process: Process,
    root: u32,
    inspect: impl FnMut(u32) -> Result<Process>,
) -> Result<bool> {
    walk_ancestry_until(process, root == 1, |process| process.pid == root, inspect)
}

/// Bind a caller to a verified, reparented daemon through a stable ancestry chain.
#[cfg(target_os = "macos")]
pub(crate) fn verify_reparented_ancestry(
    pid: u32,
    mut owns_daemon: impl FnMut(u32) -> bool,
) -> bool {
    inspect(pid)
        .and_then(|process| {
            walk_ancestry_until(
                process,
                false,
                |ancestor| ancestor.parent == 1 && owns_daemon(ancestor.pid),
                inspect,
            )
        })
        .unwrap_or(false)
}

fn walk_ancestry_until(
    mut process: Process,
    include_init: bool,
    mut accepts: impl FnMut(Process) -> bool,
    mut inspect: impl FnMut(u32) -> Result<Process>,
) -> Result<bool> {
    let mut ancestry: Vec<Process> = Vec::new();
    for _ in 0..MAX_ANCESTRY {
        ancestry.push(process);
        if accepts(process) {
            // Reparenting or PID reuse during the walk must not manufacture an edge.
            // Include the matched anchor: daemon verification may run a helper.
            for observed in ancestry {
                if inspect(observed.pid)? != observed {
                    return Err(denied());
                }
            }
            return Ok(true);
        }
        if process.parent == 0
            || (process.parent == 1 && !include_init)
            || process.parent == process.pid
        {
            return Ok(false);
        }
        process = inspect(process.parent)?;
    }
    Err(denied())
}

#[cfg(target_os = "linux")]
fn inspect(pid: u32) -> Result<Process> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|_| denied())?;
    parse_stat(pid, &stat).ok_or_else(denied)
}

#[cfg(target_os = "linux")]
fn parse_stat(pid: u32, stat: &str) -> Option<Process> {
    // comm is parenthesized and can itself contain spaces and parentheses.
    let (_, fields) = stat.rsplit_once(") ")?;
    let mut fields = fields.split_whitespace();
    fields.next()?;
    let parent = fields.next()?.parse().ok()?;
    let start = fields.nth(17)?.parse().ok()?;
    Some(Process {
        pid,
        parent,
        birth: (start, 0),
    })
}

#[cfg(target_os = "macos")]
fn inspect(pid: u32) -> Result<Process> {
    // SAFETY: proc_bsdinfo is plain data; proc_pidinfo writes at most size bytes.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of_val(&info) as i32;
    // SAFETY: info is a valid, correctly sized output buffer for this flavor.
    let ret = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if ret != size || info.pbi_pid != pid {
        return Err(denied());
    }
    Ok(Process {
        pid,
        parent: info.pbi_ppid,
        birth: (info.pbi_start_tvsec, info.pbi_start_tvusec),
    })
}

#[cfg(target_os = "linux")]
struct PeerLifetime(std::os::fd::OwnedFd);

#[cfg(target_os = "linux")]
impl PeerLifetime {
    fn new(socket: RawFd) -> Result<Self> {
        use std::os::fd::{FromRawFd, OwnedFd};
        let [fd] = socket_option(socket, libc::SOL_SOCKET, libc::SO_PEERPIDFD).map_err(|err| {
            NonoError::SandboxInit(format!(
                "cannot authenticate socket peer lifetime (SO_PEERPIDFD requires Linux 6.5+): {err}"
            ))
        })?;
        let fd = i32::try_from(fd).map_err(|_| denied())?;
        // SAFETY: SO_PEERPIDFD returned a new, owned descriptor.
        let lifetime = Self(unsafe { OwnedFd::from_raw_fd(fd) });
        lifetime.verify(socket)?;
        Ok(lifetime)
    }

    fn verify(&self, _socket: RawFd) -> Result<()> {
        use std::os::fd::AsRawFd;
        let mut pollfd = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pollfd points to one initialized pollfd; this never blocks.
        if unsafe { libc::poll(&mut pollfd, 1, 0) } != 0 {
            return Err(denied());
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
struct PeerLifetime([u32; 8]);

#[cfg(target_os = "macos")]
impl PeerLifetime {
    fn new(socket: RawFd) -> Result<Self> {
        Ok(Self(Self::token(socket)?))
    }

    fn token(socket: RawFd) -> Result<[u32; 8]> {
        socket_option(socket, libc::SOL_LOCAL, libc::LOCAL_PEERTOKEN)
    }

    fn verify(&self, socket: RawFd) -> Result<()> {
        if Self::token(socket)? != self.0 {
            return Err(denied());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};

    #[test]
    fn authenticates_a_named_connection_from_this_process() {
        let dir = tempfile::Builder::new()
            .prefix("session-auth-")
            .tempdir_in("/tmp")
            .expect("tempdir");
        let path = dir.path().join("s");
        let listener = UnixListener::bind(&path).expect("bind");
        let _client = UnixStream::connect(&path).expect("connect");
        let (server, _) = listener.accept().expect("accept");
        let result = authenticate(server.as_raw_fd(), true, |_| false);
        if validate_support(true).is_ok() {
            assert_eq!(result.expect("authenticate"), std::process::id());
        } else {
            assert!(
                result.is_err(),
                "unsupported authentication must fail closed"
            );
        }
        assert_eq!(
            authenticate(server.as_raw_fd(), false, |_| panic!(
                "disabled authentication must not inspect lineage"
            ))
            .expect("default authentication"),
            std::process::id()
        );
    }

    #[test]
    fn ancestry_does_not_accept_an_unrelated_root() {
        let process = inspect(std::process::id()).expect("inspect self");
        assert!(!walk_ancestry(process, u32::MAX, inspect).expect("walk"));
    }

    #[test]
    fn ancestry_failure_requires_independent_lineage_proof() {
        let caller = Process {
            pid: 42,
            parent: 43,
            birth: (1, 0),
        };
        for owns_caller in [false, true] {
            let mut fallback_called = false;
            let result = verify_membership(
                caller,
                44,
                |pid| {
                    assert_eq!(pid, caller.pid);
                    fallback_called = true;
                    owns_caller
                },
                |pid| {
                    assert_eq!(pid, caller.parent);
                    Err(denied())
                },
            );
            assert!(
                fallback_called,
                "an unreadable ancestor must allow a lineage check"
            );
            assert_eq!(result.is_ok(), owns_caller);
        }
    }

    #[test]
    fn verified_ancestry_does_not_consult_orphan_lineage() {
        let root = Process {
            pid: 44,
            parent: 1,
            birth: (0, 0),
        };
        let caller = Process {
            pid: 42,
            parent: root.pid,
            birth: (1, 0),
        };
        verify_membership(
            caller,
            root.pid,
            |_| panic!("verified descendants do not need orphan lineage"),
            |pid| match pid {
                42 => Ok(caller),
                44 => Ok(root),
                _ => panic!("unexpected ancestor {pid}"),
            },
        )
        .expect("verified descendant");
    }

    #[test]
    fn unrelated_ancestry_requires_independent_lineage_proof() {
        let caller = Process {
            pid: 42,
            parent: 1,
            birth: (1, 0),
        };
        for owns_caller in [false, true] {
            let result = verify_membership(
                caller,
                44,
                |pid| {
                    assert_eq!(pid, caller.pid);
                    owns_caller
                },
                |_| panic!("ancestry ends before the supervisor"),
            );
            assert_eq!(result.is_ok(), owns_caller);
        }
    }

    #[test]
    fn authenticates_descendants_when_supervisor_is_pid_one() {
        let root = Process {
            pid: 1,
            parent: 0,
            birth: (0, 0),
        };
        let child = Process {
            pid: 42,
            parent: 1,
            birth: (1, 0),
        };
        let grandchild = Process {
            pid: 43,
            parent: 42,
            birth: (2, 0),
        };
        for caller in [child, grandchild] {
            assert!(
                walk_ancestry(caller, root.pid, |pid| match pid {
                    1 => Ok(root),
                    42 => Ok(child),
                    43 => Ok(grandchild),
                    _ => panic!("unexpected ancestor {pid}"),
                })
                .expect("walk to PID 1")
            );
        }
    }

    #[test]
    fn rejects_ancestry_that_ends_before_the_supervisor() {
        for parent in [0, 1, 42] {
            let caller = Process {
                pid: 42,
                parent,
                birth: (1, 0),
            };
            assert!(
                !walk_ancestry(caller, 44, |_| panic!("must not inspect past ancestry end"))
                    .expect("unrelated ancestry")
            );
        }
    }

    #[test]
    fn verified_anchor_rechecks_the_entire_chain_after_attribution() {
        use std::cell::Cell;

        let caller = Process {
            pid: 42,
            parent: 43,
            birth: (3, 0),
        };
        let parent = Process {
            pid: 43,
            parent: 44,
            birth: (2, 0),
        };
        let daemon = Process {
            pid: 44,
            parent: 1,
            birth: (1, 0),
        };
        for changed in [
            None,
            Some(Process {
                parent: 99,
                ..caller
            }),
            Some(Process {
                birth: (4, 0),
                ..caller
            }),
            Some(Process {
                parent: 99,
                ..parent
            }),
            Some(Process {
                birth: (4, 0),
                ..parent
            }),
            Some(Process {
                parent: 99,
                ..daemon
            }),
            Some(Process {
                birth: (4, 0),
                ..daemon
            }),
        ] {
            let attributed = Cell::new(false);
            let result = walk_ancestry_until(
                caller,
                false,
                |process| {
                    if process.parent != 1 {
                        return false;
                    }
                    assert_eq!(process.pid, daemon.pid);
                    attributed.set(true);
                    true
                },
                |pid| {
                    if attributed.get()
                        && let Some(changed) = changed.filter(|changed| changed.pid == pid)
                    {
                        return Ok(changed);
                    }
                    [caller, parent, daemon]
                        .into_iter()
                        .find(|process| process.pid == pid)
                        .ok_or_else(denied)
                },
            );
            assert!(attributed.get());
            assert_eq!(result.is_ok_and(|owned| owned), changed.is_none());
        }
    }

    #[test]
    fn rejects_reparenting_and_pid_reuse_during_authentication() {
        let child = Process {
            pid: 42,
            parent: 43,
            birth: (1, 0),
        };
        let parent = Process {
            pid: 43,
            parent: 44,
            birth: (0, 0),
        };
        let root = Process {
            pid: 44,
            parent: 1,
            birth: (0, 0),
        };
        for changed in [
            Process { parent: 1, ..child },
            Process {
                birth: (2, 0),
                ..child
            },
        ] {
            let result = walk_ancestry(child, root.pid, |pid| match pid {
                42 => Ok(changed),
                43 => Ok(parent),
                44 => Ok(root),
                _ => Err(denied()),
            });
            assert!(result.is_err(), "a changed process must not authenticate");
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_stat_with_parentheses_in_comm() {
        let stat = format!("42 (a ) (b) S 12 {}987 0", "0 ".repeat(17));
        let process = parse_stat(42, &stat).expect("parse");
        assert_eq!(process.parent, 12);
        assert_eq!(process.birth, (987, 0));
        assert!(parse_stat(42, "42 (truncated) S 12").is_none());
    }
}
