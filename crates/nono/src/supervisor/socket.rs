//! Unix socket IPC for supervisor-child communication
//!
//! Provides [`SupervisorSocket`] for creating and managing the Unix domain socket
//! used for capability expansion requests between a sandboxed child and its
//! unsandboxed supervisor parent.
//!
//! The protocol uses length-prefixed JSON messages. File descriptors are passed
//! via `SCM_RIGHTS` ancillary data when the supervisor grants access to a path.

use crate::error::{NonoError, Result};
use crate::supervisor::types::{SupervisorMessage, SupervisorResponse};
use std::io::{Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use tracing::warn;

/// Length prefix size: 4 bytes (u32 big-endian)
const LENGTH_PREFIX_SIZE: usize = 4;

/// Maximum message size: 64 KiB (prevents memory exhaustion from malicious messages)
const MAX_MESSAGE_SIZE: u32 = 64 * 1024;
const SCM_RIGHTS_BUFFER_CAPACITY: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

/// A Unix domain socket for supervisor IPC.
///
/// Created by the supervisor before fork. The child inherits one end via the
/// forked file descriptor table, or the fd is explicitly passed.
///
/// # Protocol
///
/// Messages are length-prefixed JSON:
/// ```text
/// [4 bytes: u32 big-endian length][N bytes: JSON payload]
/// ```
///
/// When granting access, the supervisor sends the response message AND passes
/// an opened file descriptor via `SCM_RIGHTS` ancillary data.
pub struct SupervisorSocket {
    stream: UnixStream,
    socket_path: Option<PathBuf>,
}

impl SupervisorSocket {
    /// Create a connected socket pair for supervisor-child IPC.
    ///
    /// Returns `(supervisor_end, child_end)`. Call this before fork:
    /// - The supervisor keeps `supervisor_end`
    /// - The child inherits `child_end` (or it's passed explicitly)
    #[must_use = "both socket ends must be used"]
    pub fn pair() -> Result<(Self, Self)> {
        let (s1, s2) = UnixStream::pair().map_err(|e| {
            NonoError::SandboxInit(format!("Failed to create supervisor socket pair: {e}"))
        })?;
        Ok((
            SupervisorSocket {
                stream: s1,
                socket_path: None,
            },
            SupervisorSocket {
                stream: s2,
                socket_path: None,
            },
        ))
    }

    /// Create a supervisor socket bound to a filesystem path.
    ///
    /// The supervisor binds and listens; the child connects after fork.
    /// The socket file is cleaned up on drop.
    pub fn bind(path: &Path) -> Result<Self> {
        let listener = bind_socket_owner_only(path)?;

        // Set permissions to 0700 (owner only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(path, perms).map_err(|e| {
                NonoError::SandboxInit(format!("Failed to set supervisor socket permissions: {e}"))
            })?;
        }

        let (stream, _addr) = listener.accept().map_err(|e| {
            NonoError::SandboxInit(format!("Failed to accept supervisor connection: {e}"))
        })?;

        Ok(SupervisorSocket {
            stream,
            socket_path: Some(path.to_path_buf()),
        })
    }

    /// Connect to a supervisor socket at the given path.
    pub fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path).map_err(|e| {
            NonoError::SandboxInit(format!(
                "Failed to connect to supervisor socket at {}: {e}",
                path.display()
            ))
        })?;
        Ok(SupervisorSocket {
            stream,
            socket_path: None,
        })
    }

    /// Wrap an existing `UnixStream` (e.g., from an inherited fd after fork).
    #[must_use]
    pub fn from_stream(stream: UnixStream) -> Self {
        SupervisorSocket {
            stream,
            socket_path: None,
        }
    }

    /// Get the raw file descriptor for this socket.
    ///
    /// Useful for passing to the child process via environment variable
    /// or for `select()`/`poll()` integration.
    #[must_use]
    pub fn as_raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    /// Send a message from child to supervisor.
    pub fn send_message(&mut self, msg: &SupervisorMessage) -> Result<()> {
        let payload = serde_json::to_vec(msg).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to serialize supervisor message: {e}"))
        })?;
        self.write_frame(&payload)
    }

    /// Receive a message from child (supervisor side).
    pub fn recv_message(&mut self) -> Result<SupervisorMessage> {
        let payload = self.read_frame()?;
        serde_json::from_slice(&payload).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to deserialize supervisor message: {e}"))
        })
    }

    /// Send a response from supervisor to child.
    pub fn send_response(&mut self, resp: &SupervisorResponse) -> Result<()> {
        let payload = serde_json::to_vec(resp).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to serialize supervisor response: {e}"))
        })?;
        self.write_frame(&payload)
    }

    /// Receive a response from supervisor (child side).
    pub fn recv_response(&mut self) -> Result<SupervisorResponse> {
        let payload = self.read_frame()?;
        serde_json::from_slice(&payload).map_err(|e| {
            NonoError::SandboxInit(format!("Failed to deserialize supervisor response: {e}"))
        })
    }

    /// Send a file descriptor to the peer via `SCM_RIGHTS`.
    ///
    /// Used by the supervisor to pass an opened fd for a granted path.
    pub fn send_fd(&self, fd: RawFd) -> Result<()> {
        send_fd_via_socket(self.stream.as_raw_fd(), fd)
    }

    /// Receive a file descriptor from the peer via `SCM_RIGHTS`.
    ///
    /// Used by the child to receive an opened fd for a granted path.
    /// Returns an `OwnedFd` that the caller is responsible for.
    pub fn recv_fd(&self) -> Result<OwnedFd> {
        recv_fd_via_socket(self.stream.as_raw_fd())
    }

    /// Authenticate the peer using platform-specific mechanisms.
    ///
    /// On Linux, uses `SO_PEERCRED` to get the peer's PID/UID/GID.
    /// On macOS, combines `LOCAL_PEERPID` and `getpeereid`.
    ///
    /// Returns the peer's PID.
    pub fn peer_pid(&self) -> Result<u32> {
        Ok(peer_credentials(self.stream.as_raw_fd())?.pid)
    }

    /// Set a read timeout on the socket.
    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> Result<()> {
        self.stream
            .set_read_timeout(timeout)
            .map_err(|e| NonoError::SandboxInit(format!("Failed to set socket read timeout: {e}")))
    }

    /// Write a length-prefixed frame to the socket.
    fn write_frame(&mut self, payload: &[u8]) -> Result<()> {
        let len = payload.len();
        if len > MAX_MESSAGE_SIZE as usize {
            return Err(NonoError::SandboxInit(format!(
                "Supervisor message too large: {len} bytes (max: {MAX_MESSAGE_SIZE})"
            )));
        }

        let len_bytes = (len as u32).to_be_bytes();
        self.stream
            .write_all(&len_bytes)
            .map_err(|e| NonoError::SandboxInit(format!("Failed to write message length: {e}")))?;
        self.stream
            .write_all(payload)
            .map_err(|e| NonoError::SandboxInit(format!("Failed to write message payload: {e}")))?;
        Ok(())
    }

    /// Read a length-prefixed frame from the socket.
    fn read_frame(&mut self) -> Result<Vec<u8>> {
        let mut len_bytes = [0u8; LENGTH_PREFIX_SIZE];
        self.stream
            .read_exact(&mut len_bytes)
            .map_err(|e| NonoError::SandboxInit(format!("Failed to read message length: {e}")))?;

        let len = u32::from_be_bytes(len_bytes);
        if len > MAX_MESSAGE_SIZE {
            return Err(NonoError::SandboxInit(format!(
                "Supervisor message too large: {len} bytes (max: {MAX_MESSAGE_SIZE})"
            )));
        }

        let mut payload = vec![0u8; len as usize];
        self.stream
            .read_exact(&mut payload)
            .map_err(|e| NonoError::SandboxInit(format!("Failed to read message payload: {e}")))?;
        Ok(payload)
    }
}

#[doc(hidden)]
pub fn send_fd_via_socket(sock_fd: RawFd, fd: RawFd) -> Result<()> {
    let mut data = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: data.len(),
    };
    // SAFETY: `CMSG_SPACE` and `CMSG_LEN` are pure libc size calculations.
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let expected_cmsg_len = unsafe { libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) } as usize;

    if cmsg_space > SCM_RIGHTS_BUFFER_CAPACITY {
        return Err(NonoError::SandboxInit(
            "Unexpected ancillary buffer size for SCM_RIGHTS send".to_string(),
        ));
    }

    let mut cmsg_buf = [0u8; SCM_RIGHTS_BUFFER_CAPACITY];
    // SAFETY: `msghdr` is plain old data and will be fully initialized below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = cmsg_space as _;

    // SAFETY: `msg` references `cmsg_buf`, which is large enough for one header.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg as *const libc::msghdr as *mut libc::msghdr) };
    if cmsg.is_null() {
        return Err(NonoError::SandboxInit(
            "Missing ancillary header for SCM_RIGHTS send".to_string(),
        ));
    }

    // SAFETY: `cmsg` points into `cmsg_buf`, which is sized for exactly one fd payload.
    unsafe {
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = expected_cmsg_len as _;
        std::ptr::copy_nonoverlapping(
            (&fd as *const RawFd).cast::<u8>(),
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<RawFd>(),
        );
    }

    // SAFETY: `sock_fd` is a valid Unix socket and `msg` points to live stack buffers.
    let sent = unsafe { libc::sendmsg(sock_fd, &msg, 0) };
    if sent < 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to send fd via SCM_RIGHTS: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

#[doc(hidden)]
pub fn recv_fd_via_socket(sock_fd: RawFd) -> Result<OwnedFd> {
    let mut data = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast::<libc::c_void>(),
        iov_len: data.len(),
    };
    // SAFETY: `CMSG_SPACE` and `CMSG_LEN` are pure libc size calculations.
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let expected_cmsg_len = unsafe { libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) } as usize;

    if cmsg_space > SCM_RIGHTS_BUFFER_CAPACITY {
        return Err(NonoError::SandboxInit(
            "Unexpected ancillary buffer size for SCM_RIGHTS receive".to_string(),
        ));
    }

    let mut cmsg_buf = [0u8; SCM_RIGHTS_BUFFER_CAPACITY];
    // SAFETY: `msghdr` is plain old data and will be fully initialized below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov as *mut libc::iovec;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr().cast::<libc::c_void>();
    msg.msg_controllen = cmsg_space as _;

    // SAFETY: `sock_fd` is a valid Unix socket and `msg` references stack buffers.
    let received = unsafe { libc::recvmsg(sock_fd, &mut msg, 0) };
    if received < 0 {
        return Err(NonoError::SandboxInit(format!(
            "Failed to receive fd via SCM_RIGHTS: {}",
            std::io::Error::last_os_error()
        )));
    }
    if received == 0 {
        return Err(NonoError::SandboxInit(
            "Socket closed while waiting for SCM_RIGHTS".to_string(),
        ));
    }
    if (msg.msg_flags & libc::MSG_CTRUNC) != 0 {
        return Err(NonoError::SandboxInit(
            "SCM_RIGHTS ancillary data was truncated".to_string(),
        ));
    }

    // SAFETY: `msg` references `cmsg_buf`, which still lives on the stack here.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg as *const libc::msghdr as *mut libc::msghdr) };
    while !cmsg.is_null() {
        // SAFETY: `cmsg` was returned by libc and points into `cmsg_buf`.
        let header = unsafe { &*cmsg };
        if header.cmsg_level == libc::SOL_SOCKET && header.cmsg_type == libc::SCM_RIGHTS {
            if (header.cmsg_len as usize) < expected_cmsg_len {
                return Err(NonoError::SandboxInit(
                    "SCM_RIGHTS ancillary data too small".to_string(),
                ));
            }

            let mut fd: RawFd = -1;
            // SAFETY: `CMSG_DATA(cmsg)` points at the fd payload for this header.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(cmsg),
                    (&mut fd as *mut RawFd).cast::<u8>(),
                    std::mem::size_of::<RawFd>(),
                );
            }
            if fd < 0 {
                return Err(NonoError::SandboxInit(
                    "Received invalid fd from SCM_RIGHTS".to_string(),
                ));
            }

            // SAFETY: The fd was just received via SCM_RIGHTS and validated.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        // SAFETY: `msg` and `cmsg` still point into the same live ancillary buffer.
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg as *const libc::msghdr as *mut libc::msghdr, cmsg) };
    }

    Err(NonoError::SandboxInit(
        "No SCM_RIGHTS data in received message".to_string(),
    ))
}

#[doc(hidden)]
pub fn peer_credentials(sock_fd: RawFd) -> Result<PeerCredentials> {
    #[cfg(target_os = "linux")]
    {
        use libc::{SO_PEERCRED, SOL_SOCKET, getsockopt, socklen_t, ucred};

        // SAFETY: `ucred` is plain old data and will be written by `getsockopt`.
        let mut cred: ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<ucred>() as socklen_t;
        let ret = unsafe {
            getsockopt(
                sock_fd,
                SOL_SOCKET,
                SO_PEERCRED,
                &mut cred as *mut ucred as *mut libc::c_void,
                &mut len,
            )
        };
        if ret < 0 {
            return Err(NonoError::SandboxInit(format!(
                "SO_PEERCRED failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(PeerCredentials {
            pid: cred.pid as u32,
            uid: cred.uid,
            gid: cred.gid,
        })
    }

    #[cfg(target_os = "macos")]
    {
        use libc::{getsockopt, socklen_t};

        const LOCAL_PEERPID: libc::c_int = 0x002;

        let mut pid: libc::pid_t = 0;
        let mut pid_len = std::mem::size_of::<libc::pid_t>() as socklen_t;
        let ret = unsafe {
            getsockopt(
                sock_fd,
                0,
                LOCAL_PEERPID,
                &mut pid as *mut libc::pid_t as *mut libc::c_void,
                &mut pid_len,
            )
        };
        if ret < 0 {
            return Err(NonoError::SandboxInit(format!(
                "LOCAL_PEERPID failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let ret = unsafe { libc::getpeereid(sock_fd, &mut uid, &mut gid) };
        if ret != 0 {
            return Err(NonoError::SandboxInit(format!(
                "getpeereid failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(PeerCredentials {
            pid: pid as u32,
            uid,
            gid,
        })
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(NonoError::UnsupportedPlatform(
            "Peer credential lookup not supported on this platform".to_string(),
        ))
    }
}

#[doc(hidden)]
#[cfg(target_os = "linux")]
pub fn peer_in_same_user_namespace(peer_pid: u32) -> Result<bool> {
    let current_ns = std::fs::read_link("/proc/self/ns/user").map_err(|e| {
        NonoError::SandboxInit(format!("Failed to read current user namespace: {e}"))
    })?;
    let peer_ns = std::fs::read_link(format!("/proc/{peer_pid}/ns/user")).map_err(|e| {
        NonoError::SandboxInit(format!(
            "Failed to read user namespace for peer pid {peer_pid}: {e}"
        ))
    })?;
    Ok(current_ns == peer_ns)
}

#[doc(hidden)]
#[cfg(not(target_os = "linux"))]
pub fn peer_in_same_user_namespace(_peer_pid: u32) -> Result<bool> {
    Ok(true)
}

/// Bind a Unix socket with restrictive permissions from creation time.
///
/// This avoids a TOCTOU window where a freshly bound socket could be more
/// permissive before `set_permissions` runs.
fn bind_socket_owner_only(path: &Path) -> Result<std::os::unix::net::UnixListener> {
    let lock = umask_guard();
    let _guard = lock.lock().map_err(|_| {
        NonoError::SandboxInit("Failed to acquire umask synchronization lock".to_string())
    })?;

    let old_umask = unsafe { libc::umask(0o077) };
    let listener = std::os::unix::net::UnixListener::bind(path).map_err(|e| {
        NonoError::SandboxInit(format!(
            "Failed to bind supervisor socket at {}: {e}",
            path.display()
        ))
    });
    unsafe {
        libc::umask(old_umask);
    }
    listener
}

fn umask_guard() -> &'static Mutex<()> {
    static UMASK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    UMASK_LOCK.get_or_init(|| Mutex::new(()))
}

impl Drop for SupervisorSocket {
    fn drop(&mut self) {
        // Clean up the socket file if we created one
        if let Some(ref path) = self.socket_path
            && let Err(e) = std::fs::remove_file(path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            warn!(
                "Failed to remove supervisor socket path {}: {}",
                path.display(),
                e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::AccessMode;
    use crate::supervisor::types::{CapabilityRequest, SupervisorMessage, SupervisorResponse};

    #[test]
    fn test_socket_pair_roundtrip() {
        let (mut supervisor, mut child) =
            SupervisorSocket::pair().expect("Failed to create socket pair");

        let request = CapabilityRequest {
            request_id: "req-001".to_string(),
            path: "/tmp/test".into(),
            access: AccessMode::Read,
            reason: Some("test access".to_string()),
            child_pid: 12345,
            session_id: "sess-001".to_string(),
        };

        // Child sends request
        child
            .send_message(&SupervisorMessage::Request(request.clone()))
            .expect("Failed to send message");

        // Supervisor receives it
        let msg = supervisor
            .recv_message()
            .expect("Failed to receive message");
        match msg {
            SupervisorMessage::Request(req) => {
                assert_eq!(req.request_id, "req-001");
                assert_eq!(req.path, PathBuf::from("/tmp/test"));
                assert_eq!(req.child_pid, 12345);
            }
            other => panic!("Expected Request, got {:?}", other),
        }

        // Supervisor sends response
        let response = SupervisorResponse::Decision {
            request_id: "req-001".to_string(),
            decision: crate::supervisor::types::ApprovalDecision::Granted,
        };
        supervisor
            .send_response(&response)
            .expect("Failed to send response");

        // Child receives it
        let resp = child.recv_response().expect("Failed to receive response");
        match resp {
            SupervisorResponse::Decision {
                request_id,
                decision,
            } => {
                assert_eq!(request_id, "req-001");
                assert!(decision.is_granted());
            }
            other => panic!("Expected Decision, got {:?}", other),
        }
    }

    #[test]
    fn test_url_open_roundtrip() {
        use crate::supervisor::types::UrlOpenRequest;

        let (mut supervisor, mut child) =
            SupervisorSocket::pair().expect("Failed to create socket pair");

        let url_request = UrlOpenRequest {
            request_id: "url-001".to_string(),
            url: "https://console.anthropic.com/oauth/authorize".to_string(),
            child_pid: 12345,
            session_id: "sess-001".to_string(),
        };

        // Child sends URL open request
        child
            .send_message(&SupervisorMessage::OpenUrl(url_request))
            .expect("Failed to send message");

        // Supervisor receives it
        let msg = supervisor
            .recv_message()
            .expect("Failed to receive message");
        match msg {
            SupervisorMessage::OpenUrl(req) => {
                assert_eq!(req.request_id, "url-001");
                assert_eq!(req.url, "https://console.anthropic.com/oauth/authorize");
            }
            other => panic!("Expected OpenUrl, got {:?}", other),
        }

        // Supervisor sends response
        let response = SupervisorResponse::UrlOpened {
            request_id: "url-001".to_string(),
            success: true,
            error: None,
        };
        supervisor
            .send_response(&response)
            .expect("Failed to send response");

        // Child receives it
        let resp = child.recv_response().expect("Failed to receive response");
        match resp {
            SupervisorResponse::UrlOpened {
                request_id,
                success,
                error,
            } => {
                assert_eq!(request_id, "url-001");
                assert!(success);
                assert!(error.is_none());
            }
            other => panic!("Expected UrlOpened, got {:?}", other),
        }
    }

    #[test]
    fn test_fd_passing() {
        let (supervisor, child) = SupervisorSocket::pair().expect("Failed to create socket pair");

        // Create a temporary file to pass
        let tmp = tempfile::NamedTempFile::new().expect("Failed to create temp file");
        let fd = tmp.as_raw_fd();

        // Supervisor sends fd
        supervisor.send_fd(fd).expect("Failed to send fd");

        // Child receives fd
        let received_fd = child.recv_fd().expect("Failed to receive fd");
        assert!(received_fd.as_raw_fd() >= 0);
    }

    #[test]
    fn test_message_too_large() {
        let (mut supervisor, _child) =
            SupervisorSocket::pair().expect("Failed to create socket pair");

        let large_payload = vec![0u8; (MAX_MESSAGE_SIZE as usize) + 1];
        let result = supervisor.write_frame(&large_payload);
        assert!(result.is_err());
    }

    #[test]
    fn test_peer_pid() {
        let (supervisor, _child) = SupervisorSocket::pair().expect("Failed to create socket pair");

        // For a socketpair in the same process, peer_pid should return our own PID
        let pid = supervisor.peer_pid().expect("Failed to get peer PID");
        assert_eq!(pid, std::process::id());
    }
}
