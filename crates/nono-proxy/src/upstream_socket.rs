//! Liveness options for upstream TCP connections.
//!
//! A CONNECT tunnel is relayed with `copy_bidirectional`, which has no idle
//! timeout of its own. When an upstream stops answering without a FIN or RST
//! (a middlebox drops the flow, the peer vanishes), the kernel alone decides
//! when the tunnel fails: with data in flight, after `tcp_retries2`
//! retransmissions (about 15 minutes on Linux); with none, never. The client
//! behind the tunnel hangs for as long.
//!
//! Two socket options bound that, set on every upstream connection once it is
//! established (the connect timeout is unchanged):
//!
//! - TCP keepalive: an idle connection is probed, and fails when the probes go
//!   unanswered: after about 60 s (30 s idle, then 3 probes 10 s apart).
//! - `TCP_USER_TIMEOUT` (Linux, Android, Fuchsia): data left unacknowledged
//!   this long fails the socket.
//!
//! The user timeout is the keepalive's whole span, not shorter. With
//! keepalive on, Linux closes the connection once a probe is out and the user
//! timeout has passed since the peer was last heard from, whatever
//! `TCP_KEEPCNT` says; a shorter timeout would end an idle connection at the
//! second probe. Matching the two (as Cloudflare's "When TCP sockets refuse to
//! die" recommends) ends a silent upstream at about 60 s whether or not data
//! is in flight.
//!
//! On macOS there is no user timeout: an idle connection fails through
//! keepalive at about 60 s, and one with data in flight at the system's
//! retransmission limit.
//!
//! A live peer acknowledges data and answers probes however long the
//! connection stays idle, so neither option shortens it. The exception is a
//! peer that holds a zero receive window: Linux applies the user timeout to
//! zero-window probing too, so one that stays closed for longer than 60 s
//! fails.

use std::time::Duration;
use tokio::net::TcpStream;
use tracing::warn;

/// Idle time before the first keepalive probe.
pub(crate) const KEEPALIVE_IDLE: Duration = Duration::from_secs(30);
/// Time between unanswered keepalive probes.
pub(crate) const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// Unanswered probes before the connection fails.
pub(crate) const KEEPALIVE_RETRIES: u32 = 3;
/// How long sent data may go unacknowledged before the connection fails.
///
/// The keepalive's whole span: Linux closes a probed connection once this has
/// passed, so anything shorter would override `KEEPALIVE_RETRIES`.
#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
pub(crate) const USER_TIMEOUT: Duration =
    KEEPALIVE_IDLE.saturating_add(KEEPALIVE_INTERVAL.saturating_mul(KEEPALIVE_RETRIES));

/// Set the liveness options on an established upstream connection.
///
/// Best effort: a connection without them still works, it only fails slowly
/// if the upstream goes silent, so an error is logged rather than returned.
pub(crate) fn set_liveness(stream: &TcpStream) {
    if let Err(e) = apply(stream) {
        warn!("Failed to set upstream TCP liveness options: {}", e);
    }
}

fn apply(stream: &TcpStream) -> std::io::Result<()> {
    let socket = socket2::SockRef::from(stream);
    let keepalive = socket2::TcpKeepalive::new().with_time(KEEPALIVE_IDLE);
    #[cfg(any(
        target_os = "android",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "netbsd",
        target_vendor = "apple",
        windows,
    ))]
    let keepalive = keepalive
        .with_interval(KEEPALIVE_INTERVAL)
        .with_retries(KEEPALIVE_RETRIES);
    socket.set_tcp_keepalive(&keepalive)?;
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    socket.set_tcp_user_timeout(Some(USER_TIMEOUT))?;
    Ok(())
}

/// Assert that `stream` carries every option [`set_liveness`] sets.
///
/// Shared by the tests of each upstream open site, so each proves its own
/// call, not only this module's.
#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[track_caller]
pub(crate) fn assert_liveness(stream: &TcpStream) {
    let socket = socket2::SockRef::from(stream);
    assert!(socket.keepalive().unwrap(), "SO_KEEPALIVE not set");
    assert_eq!(socket.tcp_keepalive_time().unwrap(), KEEPALIVE_IDLE);
    #[cfg(any(
        target_os = "android",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "linux",
        target_os = "netbsd",
        target_vendor = "apple",
    ))]
    {
        assert_eq!(socket.tcp_keepalive_interval().unwrap(), KEEPALIVE_INTERVAL);
        assert_eq!(socket.tcp_keepalive_retries().unwrap(), KEEPALIVE_RETRIES);
    }
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    assert_eq!(socket.tcp_user_timeout().unwrap(), Some(USER_TIMEOUT));
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn set_liveness_sets_keepalive_and_user_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let socket = socket2::SockRef::from(&stream);
        assert!(!socket.keepalive().unwrap(), "keepalive is off by default");

        set_liveness(&stream);

        assert_liveness(&stream);
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[test]
    fn user_timeout_spans_the_keepalive() {
        assert_eq!(USER_TIMEOUT, Duration::from_secs(60));
    }
}
