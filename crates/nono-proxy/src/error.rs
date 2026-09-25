//! Error types for the nono-proxy crate.

use thiserror::Error;

/// Errors that can occur in the network proxy.
#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("Proxy bind failed on {addr}: {source}")]
    Bind {
        addr: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Host denied by filter: {host}: {reason}")]
    HostDenied { host: String, reason: String },

    #[error("Invalid session token")]
    InvalidToken,

    #[error("Unknown service prefix: {prefix}")]
    UnknownService { prefix: String },

    #[error("Upstream connection failed to {host}: {reason}")]
    UpstreamConnect { host: String, reason: String },

    #[error("External proxy error: {0}")]
    ExternalProxy(String),

    #[error("Credential loading error: {0}")]
    Credential(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("OAuth capture keystore error: {0}")]
    Keystore(String),

    #[error("HTTP parse error: {0}")]
    HttpParse(String),

    #[error("OAuth2 token exchange error: {0}")]
    OAuth2Exchange(String),

    #[error("Proxy shutdown")]
    Shutdown,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type alias for proxy operations.
pub type Result<T> = std::result::Result<T, ProxyError>;
