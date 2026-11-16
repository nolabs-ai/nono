//! Bind a live peer PID to the actual connected endpoint. LOCAL_PEERTOKEN
//! looks up the socket's recorded PID and alone cannot exclude reuse before
//! its first read. Ownership supplements, never replaces, lineage and identity.

use super::denied;
use nix::libc;
use nono::{NonoError, Result};
use std::mem::{size_of, size_of_val};
use std::os::fd::RawFd;

const PROC_PIDFDSOCKETINFO: i32 = 3;
const SOCKINFO_UN: i32 = 3;
const MAX_FDS: usize = 65_536;
const SCAN_ATTEMPTS: usize = 2;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Endpoints {
    local: u64,
    peer: u64,
}

impl Endpoints {
    fn connects_to(self, other: Self) -> bool {
        self.local == other.peer && self.peer == other.local
    }
}

pub(super) fn verify_ownership(socket: RawFd, pid: u32) -> Result<()> {
    let pid = i32::try_from(pid).map_err(|_| denied())?;
    let own_pid = i32::try_from(std::process::id()).map_err(|_| denied())?;
    let expected = socket_endpoints(own_pid, socket)?.ok_or_else(denied)?;
    // A helper may dup/close descriptors between enumeration and inspection.
    // Retry a bounded number of times; only a positive reciprocal match grants
    // access, even if the descriptor list grew or a descriptor disappeared.
    for _ in 0..SCAN_ATTEMPTS {
        for entry in descriptors(pid)? {
            if entry.proc_fdtype != libc::PROX_FDTYPE_SOCKET as u32 {
                continue;
            }
            if socket_endpoints(pid, entry.proc_fd)?.is_some_and(|peer| expected.connects_to(peer))
            {
                if socket_endpoints(own_pid, socket)? == Some(expected) {
                    return Ok(());
                }
                return Err(denied());
            }
        }
    }
    Err(denied())
}

fn descriptor_capacity(bytes: i32) -> Result<usize> {
    let bytes = usize::try_from(bytes).map_err(|_| denied())?;
    if bytes == 0 || bytes % size_of::<libc::proc_fdinfo>() != 0 {
        return Err(denied());
    }
    let count = bytes / size_of::<libc::proc_fdinfo>();
    if count > MAX_FDS {
        return Err(denied());
    }
    Ok(count.saturating_add(16).min(MAX_FDS))
}

fn descriptors(pid: i32) -> Result<Vec<libc::proc_fdinfo>> {
    // SAFETY: a null buffer with size zero requests only the required size.
    let bytes =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if bytes <= 0 {
        return Err(inspection_failed("list socket peer descriptors"));
    }
    let mut entries = vec![
        libc::proc_fdinfo {
            proc_fd: -1,
            proc_fdtype: 0
        };
        descriptor_capacity(bytes)?
    ];
    let size = i32::try_from(size_of_val(entries.as_slice())).map_err(|_| denied())?;
    // SAFETY: entries is initialized plain data with exactly size writable bytes.
    let used = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            entries.as_mut_ptr().cast(),
            size,
        )
    };
    if used <= 0 {
        return Err(inspection_failed("list socket peer descriptors"));
    }
    let used = usize::try_from(used).map_err(|_| denied())?;
    if used > size as usize || used % size_of::<libc::proc_fdinfo>() != 0 {
        return Err(denied());
    }
    entries.truncate(used / size_of::<libc::proc_fdinfo>());
    Ok(entries)
}

fn socket_endpoints(pid: i32, fd: RawFd) -> Result<Option<Endpoints>> {
    // SAFETY: SocketFdInfo contains only integers and integer arrays. Every bit
    // pattern is valid, and proc_pidfdinfo receives its full writable size.
    let mut info: SocketFdInfo = unsafe { std::mem::zeroed() };
    let size = i32::try_from(size_of_val(&info)).map_err(|_| denied())?;
    // SAFETY: info is a correctly sized output buffer for PROC_PIDFDSOCKETINFO.
    let used = unsafe {
        libc::proc_pidfdinfo(
            pid,
            fd,
            PROC_PIDFDSOCKETINFO,
            (&mut info as *mut SocketFdInfo).cast(),
            size,
        )
    };
    if used <= 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            // The descriptor was closed or reused after enumeration.
            Some(libc::EBADF | libc::ENOTSOCK) => Ok(None),
            _ => Err(NonoError::SandboxInit(format!(
                "cannot inspect socket peer endpoint: {error}"
            ))),
        };
    }
    if used != size {
        return Err(denied());
    }
    let socket = info.socket;
    if socket.kind != SOCKINFO_UN
        || socket.family != libc::AF_UNIX
        || socket.socket_type != libc::SOCK_STREAM
        || socket.local == 0
        || socket.unix.peer == 0
    {
        return Ok(None);
    }
    Ok(Some(Endpoints {
        local: socket.local,
        peer: socket.unix.peer,
    }))
}

fn inspection_failed(action: &str) -> NonoError {
    NonoError::SandboxInit(format!(
        "cannot {action}: {}",
        std::io::Error::last_os_error()
    ))
}

// Layouts from the public macOS <sys/proc_info.h>:
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h
// libc already supplies
// vinfo_stat and proc_fdinfo. The native SDK test checks sizes and offsets,
// including that un_sockinfo is the largest soi_proto union member.
#[repr(C)]
struct FileInfo {
    open_flags: u32,
    status: u32,
    offset: i64,
    kind: i32,
    guard_flags: u32,
}

#[repr(C)]
struct SocketBuffer {
    bytes: u32,
    high_water: u32,
    mbufs: u32,
    mbuf_max: u32,
    low_water: u32,
    flags: i16,
    timeout: i16,
}

#[repr(C)]
struct UnixSocketInfo {
    peer: u64,
    peer_pcb: u64,
    addresses: [[u8; libc::SOCK_MAXADDRLEN as usize]; 2],
}

#[repr(C)]
struct SocketInfo {
    stat: libc::vinfo_stat,
    local: u64,
    pcb: u64,
    socket_type: i32,
    protocol: i32,
    family: i32,
    options: i16,
    linger: i16,
    state: i16,
    queue_length: i16,
    incomplete_queue_length: i16,
    queue_limit: i16,
    timeout: i16,
    error: u16,
    out_of_band_mark: u32,
    receive: SocketBuffer,
    send: SocketBuffer,
    kind: i32,
    reserved: u32,
    // Largest member of the C soi_proto union; read only for SOCKINFO_UN.
    unix: UnixSocketInfo,
}

#[repr(C)]
struct SocketFdInfo {
    file: FileInfo,
    socket: SocketInfo,
}

#[cfg(test)]
mod tests;
