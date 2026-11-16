use super::*;
use nono::supervisor::socket::{peer_credentials, recv_fd_via_socket, send_fd_via_socket};
use std::io::{Read, Write};
use std::mem::{align_of, offset_of};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

#[test]
fn native_sdk_layout_matches_rust() {
    let dir = tempfile::tempdir().expect("layout directory");
    let source = dir.path().join("layout.c");
    let executable = dir.path().join("layout");
    std::fs::write(&source, include_str!("layout.c")).expect("write C fixture");
    let compiler = Command::new("cc")
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .expect("compile against the native SDK");
    assert!(
        compiler.status.success(),
        "{}",
        String::from_utf8_lossy(&compiler.stderr)
    );
    let output = Command::new(executable).output().expect("native layouts");
    assert!(output.status.success());
    let native: Vec<usize> = std::str::from_utf8(&output.stdout)
        .expect("layout numbers")
        .split_whitespace()
        .map(|value| value.parse().expect("layout number"))
        .collect();
    assert_eq!(
        native,
        [
            size_of::<SocketFdInfo>(),
            align_of::<SocketFdInfo>(),
            offset_of!(SocketFdInfo, socket),
            size_of::<FileInfo>(),
            size_of::<libc::vinfo_stat>(),
            size_of::<SocketInfo>(),
            align_of::<SocketInfo>(),
            offset_of!(SocketInfo, local),
            offset_of!(SocketInfo, socket_type),
            offset_of!(SocketInfo, family),
            offset_of!(SocketInfo, kind),
            offset_of!(SocketInfo, unix),
            size_of::<UnixSocketInfo>(),
            align_of::<UnixSocketInfo>(),
            offset_of!(UnixSocketInfo, peer),
            size_of::<UnixSocketInfo>(),
            align_of::<UnixSocketInfo>(),
            size_of::<SocketBuffer>(),
            size_of::<libc::proc_fdinfo>(),
            offset_of!(libc::proc_fdinfo, proc_fdtype),
        ]
    );
}

#[test]
fn descriptor_enumeration_is_bounded_and_aligned() {
    let width = size_of::<libc::proc_fdinfo>() as i32;
    for invalid in [-1, 0, width - 1, (MAX_FDS as i32 + 1) * width] {
        assert!(descriptor_capacity(invalid).is_err());
    }
    assert_eq!(descriptor_capacity(width).expect("one fd"), 17);
    assert_eq!(
        descriptor_capacity(MAX_FDS as i32 * width).expect("maximum"),
        MAX_FDS
    );
}

#[test]
fn invalid_or_disconnected_endpoints_cannot_authenticate() {
    let (socket, peer) = UnixStream::pair().expect("socket pair");
    assert!(verify_ownership(socket.as_raw_fd(), u32::MAX).is_err());
    assert!(verify_ownership(-1, std::process::id()).is_err());
    verify_ownership(socket.as_raw_fd(), std::process::id()).expect("owns socket pair");
    drop(peer);
    assert!(verify_ownership(socket.as_raw_fd(), std::process::id()).is_err());
}

fn accept(listener: &UnixListener) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).expect("blocking stream");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("read timeout");
                stream
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .expect("write timeout");
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "helper did not connect");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("accept: {error}"),
        }
    }
}

fn acknowledged(control: &mut UnixStream) {
    let mut byte = [0];
    control
        .read_exact(&mut byte)
        .expect("helper acknowledgement");
    assert_eq!(byte, [b'r']);
}

fn helper(root: &Path) {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    let mut data = Some(UnixStream::connect(root.join("data")).expect("data connection"));
    let mut control = UnixStream::connect(root.join("control")).expect("control connection");
    let mut churn: Option<(Arc<AtomicBool>, std::thread::JoinHandle<UnixStream>)> = None;
    control.write_all(b"r").expect("ready");
    loop {
        let mut command = [0];
        if control.read_exact(&mut command).is_err() {
            break;
        }
        match command[0] {
            b'd' => {
                let duplicate = data
                    .as_ref()
                    .expect("data socket")
                    .try_clone()
                    .expect("dup");
                data = Some(duplicate);
            }
            b't' => {
                let original = data.take().expect("data socket");
                send_fd_via_socket(control.as_raw_fd(), original.as_raw_fd()).expect("transfer");
                drop(original);
            }
            b'c' => {
                let mut socket = data.take().expect("data socket");
                let stop = Arc::new(AtomicBool::new(false));
                let worker_stop = Arc::clone(&stop);
                let worker = std::thread::spawn(move || {
                    while !worker_stop.load(Ordering::Relaxed) {
                        socket = socket.try_clone().expect("rotate descriptor");
                    }
                    socket
                });
                churn = Some((stop, worker));
            }
            b's' => {
                let (stop, worker) = churn.take().expect("churn worker");
                stop.store(true, Ordering::Relaxed);
                data = Some(worker.join().expect("stop churn"));
            }
            b'x' => break,
            other => panic!("unexpected command {other}"),
        }
        control.write_all(b"r").expect("acknowledge");
    }
    if let Some((stop, worker)) = churn {
        stop.store(true, Ordering::Relaxed);
        worker.join().expect("stop churn on disconnect");
    }
}

struct Reap(Child);

impl Drop for Reap {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[test]
fn authentication_requires_the_claimed_process_to_hold_the_peer_endpoint() {
    const ROLE: &str = "NONO_TEST_SOCKET_OWNERSHIP";
    if let Some(root) = std::env::var_os(ROLE) {
        helper(Path::new(&root));
        return;
    }
    let dir = tempfile::Builder::new()
        .prefix("socket-owner-")
        .tempdir_in("/tmp")
        .expect("tempdir");
    let data_listener = UnixListener::bind(dir.path().join("data")).expect("data listener");
    let control_listener =
        UnixListener::bind(dir.path().join("control")).expect("control listener");
    data_listener.set_nonblocking(true).expect("nonblocking");
    control_listener.set_nonblocking(true).expect("nonblocking");
    let mut child = Reap(Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", "session_auth::macos::tests::authentication_requires_the_claimed_process_to_hold_the_peer_endpoint", "--nocapture", "--test-threads=1"])
        .env(ROLE, dir.path())
        .spawn().expect("helper"));
    let data = accept(&data_listener);
    let mut control = accept(&control_listener);
    acknowledged(&mut control);
    let pid = child.0.id();
    let expected = socket_endpoints(std::process::id() as i32, data.as_raw_fd())
        .expect("inspect")
        .expect("connected");
    assert!(
        verify_ownership(data.as_raw_fd(), std::process::id()).is_err(),
        "accepted end is not the peer end"
    );
    assert_eq!(
        crate::session_auth::authenticate(data.as_raw_fd(), true, |_| false).expect("own child"),
        pid
    );

    control.write_all(b"d").expect("duplicate data fd");
    acknowledged(&mut control);
    verify_ownership(data.as_raw_fd(), pid).expect("dup preserves ownership");

    control.write_all(b"c").expect("start descriptor churn");
    acknowledged(&mut control);
    for _ in 0..500 {
        if let Err(error) = verify_ownership(data.as_raw_fd(), pid) {
            assert!(matches!(error, NonoError::SandboxInit(reason) if reason ==
                "socket caller does not belong to this nono session"));
        }
        assert!(verify_ownership(data.as_raw_fd(), std::process::id()).is_err());
    }
    control.write_all(b"s").expect("stop descriptor churn");
    acknowledged(&mut control);
    verify_ownership(data.as_raw_fd(), pid).expect("stable descriptor remains usable");

    control.write_all(b"t").expect("transfer data fd");
    let transferred = recv_fd_via_socket(control.as_raw_fd()).expect("receive endpoint");
    acknowledged(&mut control);
    assert!(
        socket_endpoints(std::process::id() as i32, data.as_raw_fd()).expect("inspect")
            == Some(expected)
    );
    assert_eq!(
        peer_credentials(data.as_raw_fd())
            .expect("recorded PID")
            .pid,
        pid
    );
    // The recorded PID is live and remains our descendant, but no longer owns
    // this connection. A PID/ancestry/token-only check would still accept it.
    assert!(crate::session_auth::authenticate(data.as_raw_fd(), true, |_| true).is_err());
    assert_eq!(
        crate::session_auth::authenticate(data.as_raw_fd(), false, |_| false)
            .expect("default mode"),
        pid
    );
    verify_ownership(data.as_raw_fd(), std::process::id()).expect("actual recipient owns peer");

    control.write_all(b"x").expect("stop helper");
    assert!(child.0.wait().expect("reap helper").success());
    assert!(verify_ownership(data.as_raw_fd(), pid).is_err());
    assert!(crate::session_auth::authenticate(data.as_raw_fd(), true, |_| true).is_err());
    drop(transferred);
    assert!(verify_ownership(data.as_raw_fd(), std::process::id()).is_err());
}
