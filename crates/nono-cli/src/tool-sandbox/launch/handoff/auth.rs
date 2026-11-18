use super::handoff_error;
use nix::libc;
use nono::Result;
use nono::supervisor::socket::peer_credentials;
use std::os::fd::RawFd;

pub(super) fn authenticate_parent(socket: RawFd) -> Result<u32> {
    let peer = peer_credentials(socket)?;
    // SAFETY: getppid and getuid have no preconditions.
    if peer.pid == 0
        || peer.pid != unsafe { libc::getppid() } as u32
        || peer.uid != unsafe { libc::getuid() }
    {
        return Err(handoff_error("connection is not from the direct parent"));
    }
    verify_image(socket, peer.pid)?;
    Ok(peer.pid)
}

fn verify_image(socket: RawFd, pid: u32) -> Result<()> {
    unsafe extern "C" {
        fn csops_audittoken(
            pid: libc::pid_t,
            op: libc::c_uint,
            data: *mut libc::c_void,
            size: libc::size_t,
            token: *const u32,
        ) -> libc::c_int;
        fn csops(
            pid: libc::pid_t,
            op: libc::c_uint,
            data: *mut libc::c_void,
            size: libc::size_t,
        ) -> libc::c_int;
    }
    let mut token = [0u32; 8];
    let mut size = std::mem::size_of_val(&token) as libc::socklen_t;
    // SAFETY: token is a correctly sized audit_token_t output buffer.
    let ret = unsafe {
        libc::getsockopt(
            socket,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if ret != 0 || size as usize != std::mem::size_of_val(&token) {
        return Err(handoff_error("cannot inspect supervisor audit identity"));
    }
    let mut parent_hash = [0u8; 20];
    let mut self_hash = [0u8; 20];
    let mut status = 0u32;
    const CS_OPS_STATUS: u32 = 0;
    const CS_OPS_CDHASH: u32 = 5;
    const CS_VALID: u32 = 1;
    // SAFETY: each csops call receives an initialized, correctly sized output.
    // The socket audit token binds the query to the parent's image at creation;
    // execing into nono after fabricating a handoff cannot authenticate it.
    let valid = unsafe {
        csops_audittoken(
            pid as i32,
            CS_OPS_STATUS,
            (&mut status as *mut u32).cast(),
            std::mem::size_of_val(&status),
            token.as_ptr(),
        ) == 0
            && status & CS_VALID != 0
            && csops_audittoken(
                pid as i32,
                CS_OPS_CDHASH,
                parent_hash.as_mut_ptr().cast(),
                parent_hash.len(),
                token.as_ptr(),
            ) == 0
            && csops(
                std::process::id() as i32,
                CS_OPS_CDHASH,
                self_hash.as_mut_ptr().cast(),
                self_hash.len(),
            ) == 0
    };
    if !valid || parent_hash != self_hash {
        return Err(handoff_error("parent is not the running nono executable"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn recognizes_the_running_image() {
        let (socket, _peer) = UnixStream::pair().expect("socket pair");
        verify_image(socket.as_raw_fd(), std::process::id()).expect("same executable");
    }

    #[test]
    fn a_socket_created_by_the_caller_is_not_a_supervisor() {
        let (socket, _peer) = UnixStream::pair().expect("socket pair");
        assert!(authenticate_parent(socket.as_raw_fd()).is_err());
    }
}
