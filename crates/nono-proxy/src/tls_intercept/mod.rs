//! TLS interception for CONNECT-mode L7 filtering and credential injection.
//!
//! When a CONNECT request targets a host that matches a route with
//! `endpoint_rules`, `credential_key`, or `oauth2`, the proxy mints a
//! per-hostname leaf certificate (signed by an ephemeral, per-session CA)
//! and terminates TLS locally so the inner request can be inspected,
//! filtered, and have its credentials swapped before being forwarded
//! upstream over the real TLS connection.
//!
//! ## Design constraints
//!
//! * **Selective interception** — only routes that need L7 visibility get
//!   intercepted. Everything else stays an opaque CONNECT tunnel.
//! * **Hard fail on cert pinning** — if the agent rejects our minted
//!   certificate (HPKP, hard-coded trust list, etc.) the connection is
//!   dropped and the failure is recorded in the audit log. We never
//!   silently fall back to a transparent tunnel for a route that asked
//!   for L7 enforcement.
//! * **Per-session ephemeral CA** — the CA private key lives only in
//!   memory (`Zeroizing<Vec<u8>>`) and is destroyed when the proxy
//!   shuts down. Only the public certificate is written to disk
//!   (mode `0o400`).
//! * **HTTP/1.1 + HTTP/2** — the inner TLS acceptor advertises both `h2`
//!   and `http/1.1` in ALPN. After the handshake the negotiated protocol
//!   determines which forwarding path is used: [`h2_forward`] for HTTP/2
//!   (gRPC) or the text-based parser in [`handle`] for HTTP/1.1.
//!
//! Module layout:
//!
//! * [`ca`] — ephemeral CA generation and zeroization
//! * [`cert_cache`] — per-hostname leaf certificate minting + cache
//! * [`acceptor`] — `rustls::ServerConfig` factory using the cache
//! * [`bundle`] — combined trust bundle (parent CA + webpki-roots + ephemeral CA)
//! * [`h2_forward`] — HTTP/2 per-stream credential injection + forwarding

pub mod acceptor;
pub mod bundle;
pub mod ca;
pub mod cert_cache;
pub(crate) mod h2_forward;
pub(crate) mod h2_probe;
pub mod handle;
pub(crate) mod http1;
pub(crate) mod websocket;

pub use acceptor::build_server_config;
pub use bundle::{BundleInputs, write_bundle};
pub use ca::EphemeralCa;
pub use cert_cache::CertCache;
pub(crate) use h2_probe::UpstreamH2Cache;
pub use handle::{InterceptCtx, InterceptUpstreamProxy, handle_intercept_connect};
