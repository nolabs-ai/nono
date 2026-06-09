//! In-process credential capture channel (proxy -> supervisor).
//!
//! The proxy uses this channel to request just-in-time credential resolution
//! for `cmd://` routes. The supervisor receives requests, runs allow-listed
//! commands, and returns credentials via oneshot response channels.
//!
//! This channel is entirely in-process (proxy and supervisor share the same
//! OS process). No serialization is needed.
//!
//! ## Protocol
//!
//! 1. Proxy encounters a `cmd://` route during request handling.
//! 2. Proxy sends `(ProxyCaptureRequest, oneshot::Sender)` via the mpsc channel.
//! 3. Supervisor listener receives the request, delegates to the broker.
//! 4. Broker checks cache → executes command on miss → caches result.
//! 5. Supervisor sends `ProxyCaptureResponse` back via the oneshot channel.
//! 6. Proxy receives the credential, injects it into the upstream request.
//!
//! The channel is created before proxy startup. The `CaptureSender` is passed
//! to the proxy; the `CaptureReceiver` is consumed by a dedicated listener
//! thread on the supervisor side. When the proxy shuts down, the sender is
//! dropped, causing the receiver to return `None` and the listener to exit.

use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

/// Request from the proxy to the supervisor for credential capture.
#[derive(Debug)]
pub struct ProxyCaptureRequest {
    /// Logical credential name from the profile (e.g., "github").
    pub credential_name: String,
    /// Session identifier for cache keying and audit correlation.
    pub session_id: String,
    /// Upstream host that triggered the request (e.g., "api.github.com").
    pub request_host: Option<String>,
    /// Request path (e.g., "/repos/owner/name").
    pub request_path: Option<String>,
    /// HTTP method (e.g., "GET", "POST").
    pub request_method: Option<String>,
}

/// Response from the supervisor to the proxy with the captured credential.
pub struct ProxyCaptureResponse {
    /// The captured credential value, or `None` on failure.
    pub credential: Option<Zeroizing<String>>,
    /// Error description if capture failed.
    pub error: Option<String>,
    /// When true, `credential` is a JSON object of header name → value that the
    /// proxy must parse and inject as multiple headers (the credential's
    /// `output: "json"` mode). When false (default), `credential` is a single
    /// secret value injected via the route's header configuration.
    pub is_header_map: bool,
}

impl std::fmt::Debug for ProxyCaptureResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyCaptureResponse")
            .field(
                "credential",
                &self.credential.as_ref().map(|_| "[REDACTED]"),
            )
            .field("error", &self.error)
            .field("is_header_map", &self.is_header_map)
            .finish()
    }
}

/// Sender half: held by the proxy to send capture requests.
pub type CaptureSender = mpsc::Sender<(ProxyCaptureRequest, oneshot::Sender<ProxyCaptureResponse>)>;

/// Receiver half: held by the supervisor to receive capture requests.
pub type CaptureReceiver =
    mpsc::Receiver<(ProxyCaptureRequest, oneshot::Sender<ProxyCaptureResponse>)>;

/// Create a credential capture channel with the given buffer size.
///
/// Returns `(sender, receiver)`. The sender is passed to the proxy at startup;
/// the receiver is consumed by the supervisor's capture listener.
#[must_use]
pub fn channel(buffer: usize) -> (CaptureSender, CaptureReceiver) {
    mpsc::channel(buffer)
}
