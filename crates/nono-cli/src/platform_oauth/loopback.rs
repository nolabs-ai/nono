//! One-shot loopback redirect receiver for the authorization code flow
//! ([RFC 8252] §7.3).
//!
//! The listener binds `127.0.0.1` on an OS-chosen port and serves exactly one
//! successful `GET /callback`: the first one carrying the expected `state`.
//! Anything else, from a stray browser connection or another local process
//! (including a sandboxed agent with localhost access), gets a minimal error
//! and is otherwise ignored, so it cannot end or hijack the sign-in. A
//! bounded number of rejected requests aborts the login to fail closed.
//!
//! The accepted callback's connection is held open while the CLI redeems the
//! code, so the browser's next page reflects the real outcome.
//!
//! [RFC 8252]: https://www.rfc-editor.org/rfc/rfc8252

use nono::{NonoError, Result};
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};
use url::Url;
use zeroize::Zeroizing;

const CALLBACK_PATH: &str = "/callback";
const MAX_REQUEST_BYTES: usize = 8 * 1024;
const MAX_REJECTED_REQUESTS: usize = 64;
const PER_CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(50);

pub(crate) struct LoopbackListener {
    listener: TcpListener,
    port: u16,
}

/// What the authorization server sent back to the redirect URI.
pub(crate) enum CallbackResult {
    Code(Zeroizing<String>),
    Error(String),
}

impl std::fmt::Debug for CallbackResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Code(_) => f.write_str("Code(<redacted>)"),
            Self::Error(code) => f.debug_tuple("Error").field(code).finish(),
        }
    }
}

/// An accepted callback whose browser response is still pending.
pub(crate) struct PendingCallback {
    pub(crate) responder: CallbackResponder,
    pub(crate) result: CallbackResult,
}

/// The held browser connection for an accepted callback.
pub(crate) struct CallbackResponder {
    stream: TcpStream,
}

impl LoopbackListener {
    pub(crate) fn bind() -> std::io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        Ok(Self { listener, port })
    }

    pub(crate) fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}{CALLBACK_PATH}", self.port)
    }

    /// Wait for the callback that matches `expected_state` and comes from
    /// `expected_issuer` (RFC 9207), until `deadline`.
    pub(crate) fn wait_for_callback(
        &self,
        expected_state: &str,
        expected_issuer: &str,
        deadline: Instant,
    ) -> Result<PendingCallback> {
        let mut rejected = 0usize;
        loop {
            if Instant::now() >= deadline {
                return Err(NonoError::ActionRequired(
                    "sign-in timed out waiting for the browser; run `nono login` again".to_string(),
                ));
            }
            let stream = match self.listener.accept() {
                Ok((stream, peer)) if peer.ip().is_loopback() => stream,
                Ok(_) => continue,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(ACCEPT_POLL_INTERVAL);
                    continue;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(NonoError::ConfigParse(format!(
                        "loopback listener failed: {error}"
                    )));
                }
            };
            match handle_connection(stream, expected_state, expected_issuer)? {
                Some(callback) => return Ok(callback),
                None => {
                    rejected = rejected.saturating_add(1);
                    if rejected >= MAX_REJECTED_REQUESTS {
                        return Err(NonoError::ActionRequired(
                            "sign-in aborted: too many unexpected requests reached the loopback \
                             listener"
                                .to_string(),
                        ));
                    }
                }
            }
        }
    }
}

impl CallbackResponder {
    /// Answer the held browser request with a redirect to `location`.
    pub(crate) fn redirect(mut self, location: &Url) {
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nCache-Control: no-store\r\n\
             Referrer-Policy: no-referrer\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        // Best effort: the browser may have gone away, and the CLI has already
        // reported the real outcome in the terminal.
        let _ = self.stream.write_all(response.as_bytes());
        let _ = self.stream.flush();
    }
}

/// Serve one connection. Returns `Ok(Some)` only for the genuine callback;
/// `Ok(None)` for anything rejected; `Err` for a callback that has the right
/// `state` but fails a security check, which aborts the login.
fn handle_connection(
    mut stream: TcpStream,
    expected_state: &str,
    expected_issuer: &str,
) -> Result<Option<PendingCallback>> {
    if stream.set_nonblocking(false).is_err()
        || stream
            .set_read_timeout(Some(PER_CONNECTION_TIMEOUT))
            .is_err()
        || stream
            .set_write_timeout(Some(PER_CONNECTION_TIMEOUT))
            .is_err()
    {
        return Ok(None);
    }
    let Some(target) = read_request_target(&mut stream) else {
        respond(&mut stream, "400 Bad Request");
        return Ok(None);
    };
    let Some(params) = parse_callback_target(&target) else {
        respond(&mut stream, "404 Not Found");
        return Ok(None);
    };
    let Some(state) = params.get("state") else {
        respond(&mut stream, "400 Bad Request");
        return Ok(None);
    };
    if aws_lc_rs::constant_time::verify_slices_are_equal(
        state.as_bytes(),
        expected_state.as_bytes(),
    )
    .is_err()
    {
        respond(&mut stream, "400 Bad Request");
        return Ok(None);
    }

    // From here the request carries the secret state, so it is the real
    // authorization response. A failed check is an attack, not noise.
    if params.get("iss").map(String::as_str) != Some(expected_issuer) {
        respond(&mut stream, "400 Bad Request");
        return Err(NonoError::ConfigParse(
            "sign-in aborted: the authorization response came from an unexpected issuer"
                .to_string(),
        ));
    }
    let result = match (params.get("code"), params.get("error")) {
        (Some(code), None) => CallbackResult::Code(super::client::validate_token_value(
            "authorization code",
            code.clone(),
        )?),
        (None, Some(error)) => CallbackResult::Error(
            super::client::validate_error_code(error)
                .unwrap_or_else(|_| "invalid_request".to_string()),
        ),
        _ => {
            respond(&mut stream, "400 Bad Request");
            return Err(NonoError::ConfigParse(
                "sign-in aborted: malformed authorization response".to_string(),
            ));
        }
    };
    Ok(Some(PendingCallback {
        responder: CallbackResponder { stream },
        result,
    }))
}

/// Read the request head and return the target of a `GET` request.
fn read_request_target(stream: &mut TcpStream) -> Option<String> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !buffer.windows(4).any(|window| window == b"\r\n\r\n") {
        if buffer.len() >= MAX_REQUEST_BYTES {
            return None;
        }
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let head = std::str::from_utf8(&buffer).ok()?;
    let request_line = head.split("\r\n").next()?;
    let mut parts = request_line.split(' ');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("GET"), Some(target), Some(version), None) if version.starts_with("HTTP/1.") => {
            Some(target.to_string())
        }
        _ => None,
    }
}

/// Parse `/callback?…` into its query parameters. Returns `None` for any
/// other path or a query that repeats a parameter (a confusion attempt).
fn parse_callback_target(target: &str) -> Option<std::collections::HashMap<String, String>> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != CALLBACK_PATH {
        return None;
    }
    let mut params = std::collections::HashMap::new();
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        if params
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return None;
        }
    }
    Some(params)
}

fn respond(stream: &mut TcpStream, status: &str) {
    let body = "nono login: request rejected\n";
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://nono.example.com";

    fn send(port: u16, request: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        let mut response = String::new();
        let _ = stream.read_to_string(&mut response);
        response
    }

    fn get(port: u16, target: &str) -> String {
        send(
            port,
            &format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
        )
    }

    fn spawn_wait(listener: LoopbackListener) -> std::thread::JoinHandle<Result<PendingCallback>> {
        std::thread::spawn(move || {
            listener.wait_for_callback(
                "expected-state",
                ISSUER,
                Instant::now() + Duration::from_secs(10),
            )
        })
    }

    #[test]
    fn redirect_uri_uses_the_ipv4_loopback_literal() {
        let listener = LoopbackListener::bind().unwrap();
        assert!(listener.redirect_uri().starts_with("http://127.0.0.1:"));
        assert!(listener.redirect_uri().ends_with("/callback"));
    }

    #[test]
    fn genuine_callback_is_accepted_after_noise_and_held_for_redirect() {
        let listener = LoopbackListener::bind().unwrap();
        let port = listener.port;
        let waiter = spawn_wait(listener);

        // Noise and forgeries are answered and ignored.
        assert!(get(port, "/favicon.ico").contains("404"));
        assert!(get(port, "/callback?code=stolen&state=wrong&iss=x").contains("400"));
        assert!(get(port, "/callback?code=c&state=expected-state&state=x").contains("404"));
        assert!(send(port, "POST /callback HTTP/1.1\r\n\r\n").contains("400"));

        let client = std::thread::spawn(move || {
            get(
                port,
                "/callback?code=the-code&state=expected-state&iss=https%3A%2F%2Fnono.example.com",
            )
        });
        let callback = waiter.join().unwrap().unwrap();
        match &callback.result {
            CallbackResult::Code(code) => assert_eq!(code.as_str(), "the-code"),
            other => panic!("unexpected {other:?}"),
        }
        callback.responder.redirect(
            &Url::parse("https://nono.example.com/platform/cli/complete?result=success").unwrap(),
        );
        let response = client.join().unwrap();
        assert!(response.starts_with("HTTP/1.1 302"));
        assert!(
            response.contains(
                "Location: https://nono.example.com/platform/cli/complete?result=success"
            )
        );
    }

    #[test]
    fn error_callback_is_reported() {
        let listener = LoopbackListener::bind().unwrap();
        let port = listener.port;
        let waiter = spawn_wait(listener);
        let client = std::thread::spawn(move || {
            get(
                port,
                "/callback?error=access_denied&state=expected-state&iss=https%3A%2F%2Fnono.example.com",
            )
        });
        let callback = waiter.join().unwrap().unwrap();
        assert!(matches!(&callback.result, CallbackResult::Error(code) if code == "access_denied"));
        drop(callback);
        let _ = client.join();
    }

    #[test]
    fn issuer_mismatch_with_valid_state_aborts() {
        let listener = LoopbackListener::bind().unwrap();
        let port = listener.port;
        let waiter = spawn_wait(listener);
        let response = get(
            port,
            "/callback?code=c&state=expected-state&iss=https%3A%2F%2Fevil.example",
        );
        assert!(response.contains("400"));
        assert!(waiter.join().unwrap().is_err());
    }

    #[test]
    fn missing_issuer_with_valid_state_aborts() {
        let listener = LoopbackListener::bind().unwrap();
        let port = listener.port;
        let waiter = spawn_wait(listener);
        get(port, "/callback?code=c&state=expected-state");
        assert!(waiter.join().unwrap().is_err());
    }

    #[test]
    fn deadline_expiry_fails_closed() {
        let listener = LoopbackListener::bind().unwrap();
        let result = listener.wait_for_callback("s", ISSUER, Instant::now());
        assert!(result.is_err());
    }

    #[test]
    fn too_many_rejected_requests_abort() {
        let listener = LoopbackListener::bind().unwrap();
        let port = listener.port;
        let waiter = spawn_wait(listener);
        for _ in 0..MAX_REJECTED_REQUESTS {
            get(port, "/nope");
        }
        assert!(waiter.join().unwrap().is_err());
    }
}
