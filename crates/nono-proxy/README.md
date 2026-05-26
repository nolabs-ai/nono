# nono-proxy

Network filtering proxy for the [nono](https://crates.io/crates/nono) sandbox.

## Overview

`nono-proxy` provides host-level network filtering and credential injection for sandboxed processes. It runs **unsandboxed** in the supervisor process while the child is restricted to connecting only to the proxy's localhost port via `NetworkMode::ProxyOnly`.

## Proxy Modes

| Mode | Module | Description |
|------|--------|-------------|
| CONNECT tunnel | `connect` | Host-filtered HTTPS tunnelling. Validates the target host against an allowlist and cloud metadata deny list, then establishes a raw TCP tunnel. TLS is end-to-end. |
| Reverse proxy | `reverse` | Credential injection for API calls. Requests to `http://127.0.0.1:<port>/<service>/...` are forwarded upstream with the real API key injected as an HTTP header. |
| External proxy | `external` | Enterprise proxy passthrough. CONNECT requests are chained through a corporate proxy with cloud metadata endpoints still denied. |

## Security Properties

- **Cloud metadata deny list is hardcoded** -- Cloud metadata hostnames (169.254.169.254, metadata.google.internal, metadata.azure.internal) are always blocked regardless of allowlist configuration. Private network addresses (RFC1918) are allowed to support enterprise environments.
- **DNS rebinding protection** -- The proxy resolves DNS, checks all resolved IPs against the link-local range (169.254.0.0/16, fe80::/10), and connects to resolved addresses (not re-resolved hostnames). This prevents DNS rebinding attacks targeting cloud metadata.
- **Session token authentication** -- Each session generates a 256-bit random token. CONNECT requests use `Proxy-Authorization` (Basic or Bearer); reverse proxy requests use a phantom token (session token sent in the service-specific auth header) with `Proxy-Authorization` as fallback for tools that cannot send the expected header.
- **Credential isolation** -- API keys are loaded from the OS keyring, stored in `Zeroizing<String>`, injected at the HTTP header level, and never exposed to the sandboxed process.
- **Constant-time token comparison** -- Prevents timing side-channel attacks on session token validation.

## Usage

```rust
use nono_proxy::{ProxyConfig, start, ProxyHandle};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ProxyConfig {
        allowed_hosts: vec![
            "api.openai.com".into(),
            "api.anthropic.com".into(),
        ],
        ..Default::default()
    };

    let handle: ProxyHandle = start(config).await?;

    // Set these in the child process environment
    let env_vars = handle.env_vars();
    // HTTP_PROXY, HTTPS_PROXY, NONO_PROXY_TOKEN, etc.

    // Shutdown when done
    handle.shutdown();
    Ok(())
}
```

## Module Structure

| Module | Purpose |
|--------|---------|
| `server` | TCP listener, connection dispatch, lifecycle |
| `filter` | Async host filtering with DNS resolution |
| `connect` | CONNECT tunnel handler |
| `reverse` | Reverse proxy with credential injection |
| `external` | External proxy passthrough |
| `credential` | Keyring-backed credential store |
| `token` | Session token generation and validation |
| `config` | Configuration types |
| `audit` | Connection audit logging |
| `error` | Error types |

## License

Apache-2.0
