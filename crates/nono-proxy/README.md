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
- **Session token authentication** -- Each session generates a 256-bit random token. CONNECT requests use `Proxy-Authorization` (Basic or Bearer); reverse proxy requests are authenticated transparently — nono sets the credential env var (e.g. `GITHUB_TOKEN`) to a phantom token inside the sandbox, so standard API clients send it automatically in the service-specific auth header (e.g. `Authorization: Bearer`), which the proxy validates before injecting the real credential.
- **Credential isolation** -- API keys are loaded from the OS keyring, stored in `Zeroizing<String>`, injected at the HTTP header level, and never exposed to the sandboxed process.
- **Constant-time token comparison** -- Prevents timing side-channel attacks on session token validation.

## Rate Limiting

Each route may declare an optional per-route request-rate limit (a
`RouteRateLimiter`) to contain a runaway or compromised agent:

```toml
[[routes]]
prefix = "openai"
upstream = "https://api.openai.com"
credential_key = "openai_api_key"

[routes.rate_limit]
requests_per_minute = 120   # token-bucket refill rate
burst = 5                   # instantaneous headroom (default 5)
max_delay_secs = 5          # longest a request waits before 429 (default 5)
```

A token bucket refills at `requests_per_minute` and holds up to `burst` tokens.
When the bucket is empty, a request is delayed until a token accrues, up to
`max_delay_secs`; a request that would wait longer is rejected with **HTTP 429**.
Overload is a bounded delay then reject -- never a human approval prompt and
never an unbounded wait (which would let a flood exhaust the proxy). See
[`docs/adr/0001-route-rate-limiter-bounded-throttle-then-reject.md`](../../docs/adr/0001-route-rate-limiter-bounded-throttle-then-reject.md).

**Scope:** the limiter acts only on **L7-visible** traffic -- reverse-proxy
routes and TLS-intercepted CONNECT. It has **no effect** on an opaque CONNECT
tunnel (a route without interception), where the proxy sees a single TCP stream
and cannot count individual requests. Use per-route interception
(`endpoint_rules` / `credential_key`) if you need request-level limiting on a
CONNECT host.

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
    // HTTP_PROXY, HTTPS_PROXY, and the phantom credential env vars (e.g. GITHUB_TOKEN).

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
