//! TLS interception for CONNECT-mode L7 filtering and credential injection.
//!
//! When a CONNECT request targets a host that matches a route with
//! `endpoint_rules`, `credential_key`, or `oauth2`, the proxy mints a
//! per-hostname leaf certificate (signed by an ephemeral, per-session CA)
//! and terminates TLS locally so the inner HTTP/1.1 request can be
//! inspected, filtered, and have its credentials swapped before being
//! forwarded upstream over the real TLS connection.
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
//! * **HTTP/1.1 only** — the inner TLS acceptor advertises only `http/1.1`
//!   in ALPN, matching the existing reverse-proxy code path.
//!
//! Module layout:
//!
//! * [`ca`] — ephemeral CA generation and zeroization
//! * [`cert_cache`] — per-hostname leaf certificate minting + cache
//! * [`acceptor`] — `rustls::ServerConfig` factory using the cache
//! * [`bundle`] — combined trust bundle (parent CA + webpki-roots + ephemeral CA)

pub mod acceptor;
pub mod bundle;
pub mod ca;
pub mod cert_cache;
pub mod handle;

pub use acceptor::build_server_config;
pub use bundle::{BundleInputs, write_bundle};
pub use ca::EphemeralCa;
pub use cert_cache::CertCache;
pub use handle::{InterceptCtx, handle_intercept_connect};
