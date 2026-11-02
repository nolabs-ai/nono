//! HTTP/1.1 over a Unix stream socket for `unix://` approval webhooks.
//!
//! ureq keeps doing the HTTP work (request framing, response parsing, body
//! limits, timeouts); this only swaps the TCP socket for a Unix one. The
//! connector ignores the resolved address and always dials the configured
//! socket, so the request URL's host is never used to pick a destination.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::Duration;

use ureq::config::Config;
use ureq::http::Uri;
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, LazyBuffers, NextTimeout, ShutdownHandle, Transport,
};
use ureq::{Agent, Error};

/// Build an agent whose every request goes to `socket`.
pub(super) fn build_agent(config: Config, socket: PathBuf) -> Agent {
    Agent::with_parts(config, UnixConnector { socket }, NoopResolver)
}

struct UnixConnector {
    socket: PathBuf,
}

impl fmt::Debug for UnixConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnixConnector")
            .field("socket", &self.socket)
            .finish()
    }
}

impl Connector<()> for UnixConnector {
    type Out = UnixTransport;

    fn connect(
        &self,
        details: &ConnectionDetails,
        _chained: Option<()>,
    ) -> Result<Option<Self::Out>, Error> {
        // A missing socket (ENOENT) or a dead helper (ECONNREFUSED) is an
        // error here, which the webhook backend turns into a denial.
        let stream = UnixStream::connect(&self.socket)?;
        let config = details.config;
        let buffers = LazyBuffers::new(config.input_buffer_size(), config.output_buffer_size());
        let transport = UnixTransport {
            stream: Arc::new(SharedStream(stream)),
            buffers,
            timeout_read: None,
            timeout_write: None,
        };
        (details.register_shutdown)(Arc::downgrade(&transport.stream) as Weak<dyn ShutdownHandle>)?;
        Ok(Some(transport))
    }
}

/// The connector never looks at the address, so skip DNS entirely.
#[derive(Debug)]
struct NoopResolver;

impl Resolver for NoopResolver {
    fn resolve(
        &self,
        _uri: &Uri,
        _config: &Config,
        _timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, Error> {
        let mut addrs = self.empty();
        addrs.push(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80)));
        Ok(addrs)
    }
}

/// Newtype so the stream can serve as ureq's [`ShutdownHandle`].
struct SharedStream(UnixStream);

impl ShutdownHandle for SharedStream {
    fn shutdown(&self) {
        // An error means the socket is already closed or shut down.
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

/// Adapted from ureq's `TcpTransport` (ureq 3.5, MIT OR Apache-2.0), with a
/// `UnixStream` underneath.
struct UnixTransport {
    stream: Arc<SharedStream>,
    buffers: LazyBuffers,
    timeout_read: Option<Duration>,
    timeout_write: Option<Duration>,
}

impl fmt::Debug for UnixTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnixTransport").finish()
    }
}

/// Only issue the `setsockopt` when the timeout actually changes.
fn update_timeout(
    timeout: NextTimeout,
    previous: &mut Option<Duration>,
    stream: &UnixStream,
    set: impl Fn(&UnixStream, Option<Duration>) -> io::Result<()>,
) -> io::Result<()> {
    let wanted = timeout.not_zero().map(|t| *t);
    if wanted != *previous {
        set(stream, wanted)?;
        *previous = wanted;
    }
    Ok(())
}

fn check(timeout: NextTimeout) -> Result<NextTimeout, Error> {
    if timeout.after.is_zero() {
        Err(Error::Timeout(timeout.reason))
    } else {
        Ok(timeout)
    }
}

fn map_io(result: io::Result<usize>, timeout: NextTimeout) -> Result<usize, Error> {
    match result {
        Ok(amount) => Ok(amount),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Err(Error::Timeout(timeout.reason))
        }
        Err(e) => Err(e.into()),
    }
}

impl Transport for UnixTransport {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }

    fn transmit_output(&mut self, amount: usize, timeout: NextTimeout) -> Result<(), Error> {
        let timeout = check(timeout.for_write())?;
        update_timeout(
            timeout,
            &mut self.timeout_write,
            &self.stream.0,
            UnixStream::set_write_timeout,
        )?;
        let output = &self.buffers.output()[..amount];
        map_io((&self.stream.0).write_all(output).map(|()| amount), timeout)?;
        Ok(())
    }

    fn await_input(&mut self, timeout: NextTimeout) -> Result<bool, Error> {
        let timeout = check(timeout.for_read())?;
        update_timeout(
            timeout,
            &mut self.timeout_read,
            &self.stream.0,
            UnixStream::set_read_timeout,
        )?;
        let input = self.buffers.input_append_buf();
        let read = loop {
            match (&self.stream.0).read(input) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                other => break other,
            }
        };
        let amount = map_io(read, timeout)?;
        self.buffers.input_appended(amount);
        Ok(amount > 0)
    }

    fn is_open(&mut self) -> bool {
        // ureq only asks this when deciding whether to pool a connection.
        // Never reuse one: each approval request dials the socket afresh.
        false
    }
}
