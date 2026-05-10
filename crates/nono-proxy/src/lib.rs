//! Network filtering proxy for the nono sandbox.
//!
//! `nono-proxy` provides three proxy modes:
//!
//! 1. **CONNECT tunnel** (`connect`) - Host-filtered HTTPS tunnelling.
//!    The proxy validates the target host against an allowlist and cloud
//!    metadata deny list, then establishes a raw TCP tunnel.
//!
//! 2. **Reverse proxy** (`reverse`) - Credential injection for API calls.
//!    Requests arrive at `http://127.0.0.1:<port>/<service>/...`, the proxy
//!    injects the real API credential and forwards to the upstream.
//!
//! 3. **External proxy** (`external`) - Enterprise proxy passthrough.
//!    CONNECT requests are chained through a corporate proxy with the
//!    default deny list enforced as a floor.
//!
//! The proxy runs **unsandboxed** in the supervisor process. The sandboxed
//! child can only reach `localhost:<port>` via `NetworkMode::ProxyOnly`.

pub mod audit;
pub mod config;
pub mod connect;
pub mod credential;
pub mod error;
pub mod external;
pub mod filter;
pub mod forward;
pub mod oauth2;
pub mod reverse;
pub mod route;
pub mod server;
pub mod tls_intercept;
pub mod token;

pub use config::ProxyConfig;
pub use error::{ProxyError, Result};
pub use server::{start, ProxyHandle};
