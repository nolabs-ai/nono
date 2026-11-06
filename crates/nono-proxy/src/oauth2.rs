//! OAuth2 `client_credentials` token exchange and caching.
//!
//! Provides [`TokenCache`] — a thread-safe cache that holds an OAuth2 access
//! token and refreshes it on demand before expiry. Designed for the reverse
//! proxy credential injection flow where the agent never sees the real
//! client_id/client_secret.
//!
//! ## Design
//!
//! - **No background tasks**: Token validity is checked on each use via
//!   [`TokenCache::get_or_refresh()`]. If the cached token is about to expire
//!   (within 30 seconds), a synchronous refresh is attempted.
//! - **Graceful degradation**: If a refresh attempt fails but a stale token
//!   exists, the stale token is returned with a warning log. This avoids
//!   transient auth-server outages from cascading into request failures.
//! - **TLS via rustls**: Uses the same `webpki-roots` + `tokio-rustls` stack
//!   as the rest of the proxy. No additional HTTP client dependencies.

use crate::error::{ProxyError, Result};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};
use zeroize::Zeroizing;

/// Buffer subtracted from `expires_in` to refresh before the token actually
/// expires. Avoids edge cases where a token expires between check and use.
const EXPIRY_BUFFER_SECS: u64 = 30;

/// Default TTL when the token endpoint omits `expires_in`.
const DEFAULT_EXPIRES_IN_SECS: u64 = 3600;

/// Timeout for the TCP connect + TLS handshake + HTTP exchange.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum response body size from the token endpoint (64 KiB).
const MAX_TOKEN_RESPONSE: usize = 64 * 1024;

// ────────────────────────────────────────────────────────────────────────────
// Public types
// ────────────────────────────────────────────────────────────────────────────

/// Resolved OAuth2 credentials ready for token exchange.
///
/// All secret fields use [`Zeroizing`] so they are zeroed on drop.
pub struct OAuth2ExchangeConfig {
    pub token_url: String,
    pub client_id: Zeroizing<String>,
    pub client_secret: Zeroizing<String>,
    pub scope: String,
}

/// Custom Debug that redacts secrets.
impl std::fmt::Debug for OAuth2ExchangeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuth2ExchangeConfig")
            .field("token_url", &self.token_url)
            .field("client_id", &"[REDACTED]")
            .field("client_secret", &"[REDACTED]")
            .field("scope", &self.scope)
            .finish()
    }
}

/// Thread-safe OAuth2 access-token cache with on-demand refresh.
pub struct TokenCache {
    token: Arc<RwLock<CachedToken>>,
    config: OAuth2ExchangeConfig,
    tls_connector: TlsConnector,
}

impl std::fmt::Debug for TokenCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenCache")
            .field("config", &self.config)
            .finish()
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Internal types
// ────────────────────────────────────────────────────────────────────────────

struct CachedToken {
    access_token: Zeroizing<String>,
    expires_at: Instant,
}

// ────────────────────────────────────────────────────────────────────────────
// TokenCache implementation
// ────────────────────────────────────────────────────────────────────────────

impl TokenCache {
    /// Create a new cache and perform the **initial** token exchange.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyError::OAuth2Exchange`] if the initial exchange fails
    /// (DNS, TCP, TLS, non-200, malformed JSON). The calling code skips the
    /// route so the proxy can still start for other routes.
    pub async fn new(config: OAuth2ExchangeConfig, tls_connector: TlsConnector) -> Result<Self> {
        let (access_token, expires_in) = exchange_token(&config, &tls_connector).await?;

        let expires_at = Instant::now() + expires_in;
        debug!(
            "OAuth2 initial token acquired, expires in {}s",
            expires_in.as_secs()
        );

        Ok(Self {
            token: Arc::new(RwLock::new(CachedToken {
                access_token,
                expires_at,
            })),
            config,
            tls_connector,
        })
    }

    /// Create a `TokenCache` with a pre-populated token (for testing).
    ///
    /// Skips the initial token exchange. Used by tests that need a cache
    /// without a real OAuth2 server.
    #[cfg(test)]
    pub(crate) fn new_from_parts(
        config: OAuth2ExchangeConfig,
        tls_connector: TlsConnector,
        token: &str,
        ttl: Duration,
    ) -> Self {
        Self {
            token: Arc::new(RwLock::new(CachedToken {
                access_token: Zeroizing::new(token.to_string()),
                expires_at: Instant::now() + ttl,
            })),
            config,
            tls_connector,
        }
    }

    /// Return a valid access token, refreshing if needed.
    ///
    /// If the cached token is still valid (expires > 30 s from now), returns
    /// the cached value without any network call.
    ///
    /// If expired, attempts one exchange. On failure, returns the **stale**
    /// token with a warning — better to try a possibly-expired token than to
    /// fail the request outright.
    pub async fn get_or_refresh(&self) -> Zeroizing<String> {
        // Fast path — token still valid.
        {
            let guard = self.token.read().await;
            if Instant::now() + Duration::from_secs(EXPIRY_BUFFER_SECS) < guard.expires_at {
                return guard.access_token.clone();
            }
        }

        // Slow path — need to refresh.
        let mut guard = self.token.write().await;

        // Double-check after acquiring write lock (another task may have refreshed).
        if Instant::now() + Duration::from_secs(EXPIRY_BUFFER_SECS) < guard.expires_at {
            return guard.access_token.clone();
        }

        match exchange_token(&self.config, &self.tls_connector).await {
            Ok((new_token, expires_in)) => {
                debug!(
                    "OAuth2 token refreshed, expires in {}s",
                    expires_in.as_secs()
                );
                guard.access_token = new_token;
                guard.expires_at = Instant::now() + expires_in;
                guard.access_token.clone()
            }
            Err(e) => {
                warn!("OAuth2 token refresh failed, returning stale token: {}", e);
                guard.access_token.clone()
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Token exchange (HTTP POST)
// ────────────────────────────────────────────────────────────────────────────

/// HTTP request-target for a token POST (`path` plus query when present).
fn token_request_target(parsed: &url::Url) -> String {
    let path = if parsed.path().is_empty() {
        "/"
    } else {
        parsed.path()
    };
    match parsed.query() {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    }
}

/// Perform a single `client_credentials` token exchange against the token
/// endpoint described in `config`.
///
/// Returns `(access_token, expires_in_duration)`.
async fn exchange_token(
    config: &OAuth2ExchangeConfig,
    tls_connector: &TlsConnector,
) -> Result<(Zeroizing<String>, Duration)> {
    let parsed = url::Url::parse(&config.token_url).map_err(|e| {
        ProxyError::OAuth2Exchange(format!("invalid token_url '{}': {}", config.token_url, e))
    })?;

    let scheme = parsed.scheme();
    let is_https = match scheme {
        "https" => true,
        "http" => {
            // HTTP is only permitted for loopback addresses (testing / local
            // mock servers). Sending a JWT-SVID or client_secret over plaintext
            // HTTP to a non-loopback host exposes the credential on the network.
            let is_loopback = parsed.host_str().is_some_and(|h| {
                h == "localhost"
                    || h.parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
            if !is_loopback {
                return Err(ProxyError::OAuth2Exchange(format!(
                    "token_url '{}' must use https:// (http:// is only permitted for loopback addresses)",
                    config.token_url
                )));
            }
            false
        }
        other => {
            return Err(ProxyError::OAuth2Exchange(format!(
                "unsupported scheme '{}' in token_url",
                other
            )));
        }
    };

    let host = parsed
        .host_str()
        .ok_or_else(|| {
            ProxyError::OAuth2Exchange(format!("missing host in token_url '{}'", config.token_url))
        })?
        .to_string();

    let default_port: u16 = if is_https { 443 } else { 80 };
    let port = parsed.port().unwrap_or(default_port);
    let path_with_query = token_request_target(&parsed);

    // ── Build form body ──────────────────────────────────────────────────
    let body = build_token_request_body(&config.client_id, &config.client_secret, &config.scope);

    // ── Build HTTP/1.1 request ───────────────────────────────────────────
    let request = Zeroizing::new(format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/x-www-form-urlencoded\r\n\
         Content-Length: {}\r\n\
         Accept: application/json\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        path_with_query,
        host,
        body.len(),
        body.as_str()
    ));

    // ── TCP + optional TLS ───────────────────────────────────────────────
    let addr = format!("{}:{}", host, port);

    let response = tokio::time::timeout(EXCHANGE_TIMEOUT, async {
        let tcp = TcpStream::connect(&addr)
            .await
            .map_err(|e| ProxyError::OAuth2Exchange(format!("TCP connect to {}: {}", addr, e)))?;

        async fn send_and_read<S: tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin>(
            stream: &mut S,
            request: &[u8],
            host: &str,
        ) -> Result<TokenHttpResponse> {
            stream
                .write_all(request)
                .await
                .map_err(|e| ProxyError::OAuth2Exchange(format!("write to {}: {}", host, e)))?;
            stream
                .flush()
                .await
                .map_err(|e| ProxyError::OAuth2Exchange(format!("flush to {}: {}", host, e)))?;
            read_http_response(stream).await
        }

        if is_https {
            let server_name =
                rustls::pki_types::ServerName::try_from(host.clone()).map_err(|_| {
                    ProxyError::OAuth2Exchange(format!("invalid TLS server name: {}", host))
                })?;

            let mut tls = tls_connector.connect(server_name, tcp).await.map_err(|e| {
                ProxyError::OAuth2Exchange(format!("TLS handshake with {}: {}", host, e))
            })?;

            send_and_read(&mut tls, request.as_bytes(), &host).await
        } else {
            let mut tcp = tcp;
            send_and_read(&mut tcp, request.as_bytes(), &host).await
        }
    })
    .await
    .map_err(|_| ProxyError::OAuth2Exchange(format!("token exchange with {} timed out", addr)))??;

    // ── Check status code ────────────────────────────────────────────────
    if !(200..300).contains(&response.status) {
        let body_preview: String = response.body.chars().take(200).collect();
        return Err(ProxyError::OAuth2Exchange(format!(
            "token endpoint returned HTTP {}: {}",
            response.status, body_preview
        )));
    }

    parse_token_response(&response.body)
}

/// A token endpoint response with its body already de-framed.
struct TokenHttpResponse {
    status: u16,
    body: Zeroizing<String>,
}

/// Read one HTTP/1.1 response from a stream, up to [`MAX_TOKEN_RESPONSE`] bytes.
///
/// A body framed by `Transfer-Encoding: chunked` or `Content-Length` is read
/// only until that framing says it is complete. Many servers close a TLS
/// connection without `close_notify`, which rustls reports as `UnexpectedEof`
/// on the next read; for a framed response that read never happens. A body
/// that ends before its framing does is an error. An unframed body is read to
/// a clean EOF, and any read error fails, since it cannot be told apart from
/// a truncated one.
async fn read_http_response<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<TokenHttpResponse> {
    let mut buf = Zeroizing::new(Vec::with_capacity(4096));

    let body_start = loop {
        if let Some(start) = find_body_start(&buf) {
            break start;
        }
        if read_more(stream, &mut buf).await? == 0 {
            return Err(ProxyError::OAuth2Exchange(
                "malformed HTTP response: no header/body separator".to_string(),
            ));
        }
    };

    let headers = std::str::from_utf8(&buf[..body_start]).map_err(|_| {
        ProxyError::OAuth2Exchange("token endpoint returned non-UTF-8 headers".to_string())
    })?;
    let status = parse_status_code(headers.lines().next().unwrap_or(""));
    let is_chunked = crate::reverse::has_chunked_transfer_encoding(headers.as_bytes());
    let content_length = crate::reverse::extract_content_length(headers.as_bytes());

    // Transfer-Encoding takes precedence over Content-Length (RFC 9112 §6.3).
    let body = if is_chunked {
        loop {
            if let Some(decoded) = decode_chunked(&buf[body_start..])? {
                break decoded;
            }
            if read_more(stream, &mut buf).await? == 0 {
                return Err(truncated_response());
            }
        }
    } else if let Some(len) = content_length {
        let end = body_start
            .checked_add(len)
            .filter(|end| *end <= MAX_TOKEN_RESPONSE)
            .ok_or_else(response_too_large)?;
        while buf.len() < end {
            if read_more(stream, &mut buf).await? == 0 {
                return Err(truncated_response());
            }
        }
        buf[body_start..end].to_vec()
    } else {
        while read_more(stream, &mut buf).await? != 0 {}
        buf[body_start..].to_vec()
    };

    let body = String::from_utf8(body).map_err(|_| {
        ProxyError::OAuth2Exchange("token endpoint returned non-UTF-8 response".to_string())
    })?;
    Ok(TokenHttpResponse {
        status,
        body: Zeroizing::new(body),
    })
}

/// Append the next read from `stream` to `buf`, enforcing [`MAX_TOKEN_RESPONSE`].
///
/// Returns the number of bytes read; `0` means a clean EOF.
async fn read_more<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
    buf: &mut Vec<u8>,
) -> Result<usize> {
    let mut tmp = Zeroizing::new([0u8; 4096]);
    let n = stream
        .read(tmp.as_mut_slice())
        .await
        .map_err(|e| ProxyError::OAuth2Exchange(format!("read response: {}", e)))?;
    if buf.len().saturating_add(n) > MAX_TOKEN_RESPONSE {
        return Err(response_too_large());
    }
    buf.extend_from_slice(&tmp[..n]);
    Ok(n)
}

/// Offset of the first body byte, once the header terminator has been read.
fn find_body_start(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| buf.windows(2).position(|w| w == b"\n\n").map(|i| i + 2))
}

fn truncated_response() -> ProxyError {
    ProxyError::OAuth2Exchange("truncated token response".to_string())
}

fn response_too_large() -> ProxyError {
    ProxyError::OAuth2Exchange(format!(
        "token response exceeds {} bytes",
        MAX_TOKEN_RESPONSE
    ))
}

/// Parse the HTTP status code from the status line.
fn parse_status_code(line: &str) -> u16 {
    // "HTTP/1.1 200 OK" -> "200"
    let mut parts = line.split_whitespace();
    parts.nth(1).and_then(|code| code.parse().ok()).unwrap_or(0)
}

// ────────────────────────────────────────────────────────────────────────────
// Request / response helpers (pub(crate) for testing)
// ────────────────────────────────────────────────────────────────────────────

/// Build the `application/x-www-form-urlencoded` body for the token request.
///
/// The `scope` parameter is omitted when empty.
fn build_token_request_body(
    client_id: &str,
    client_secret: &str,
    scope: &str,
) -> Zeroizing<String> {
    let mut body = Zeroizing::new(format!(
        "grant_type=client_credentials&client_id={}&client_secret={}",
        urlencoding::encode(client_id),
        urlencoding::encode(client_secret),
    ));
    if !scope.is_empty() {
        body.push_str(&format!("&scope={}", urlencoding::encode(scope)));
    }
    body
}

/// Parse a standard OAuth2 token response JSON.
///
/// Expects `{"access_token": "...", "expires_in": 3600, ...}`.
/// - `access_token` is required.
/// - `expires_in` defaults to [`DEFAULT_EXPIRES_IN_SECS`] if missing.
fn parse_token_response(json: &str) -> Result<(Zeroizing<String>, Duration)> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|e| {
        ProxyError::OAuth2Exchange(format!("invalid JSON from token endpoint: {}", e))
    })?;

    let access_token = value
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ProxyError::OAuth2Exchange("token response missing 'access_token' field".to_string())
        })?;

    let expires_in_secs = value
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(DEFAULT_EXPIRES_IN_SECS);

    Ok((
        Zeroizing::new(access_token.to_string()),
        Duration::from_secs(expires_in_secs),
    ))
}

// ────────────────────────────────────────────────────────────────────────────
// SPIFFE JWT-SVID client assertion token cache
// ────────────────────────────────────────────────────────────────────────────

/// Like [`TokenCache`] but uses a SPIFFE JWT-SVID as the OAuth2 `client_assertion`
/// instead of a client_id/secret pair. Exchanges via `jwt-bearer` grant type.
pub struct SpiffeAssertionTokenCache {
    token: Arc<RwLock<CachedToken>>,
    jwt_source: Arc<crate::spiffe::SpiffeJwtSource>,
    token_url: String,
    assertion_audience: Vec<String>,
    extra_params: Vec<(String, String)>,
    tls_connector: TlsConnector,
    pub workload_spiffe_id: String,
}

impl std::fmt::Debug for SpiffeAssertionTokenCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeAssertionTokenCache")
            .field("token_url", &self.token_url)
            .finish()
    }
}

impl SpiffeAssertionTokenCache {
    pub async fn new(
        token_url: String,
        jwt_source: Arc<crate::spiffe::SpiffeJwtSource>,
        assertion_audience: Vec<String>,
        extra_params: Vec<(String, String)>,
        tls_connector: TlsConnector,
    ) -> Result<Self> {
        let (access_token, expires_in, workload_spiffe_id) = exchange_jwt_assertion(
            &token_url,
            &jwt_source,
            &assertion_audience,
            &extra_params,
            &tls_connector,
        )
        .await?;

        Ok(Self {
            token: Arc::new(RwLock::new(CachedToken {
                access_token,
                expires_at: Instant::now() + expires_in,
            })),
            jwt_source,
            token_url,
            assertion_audience,
            extra_params,
            tls_connector,
            workload_spiffe_id,
        })
    }

    pub async fn get_or_refresh(&self) -> Result<Zeroizing<String>> {
        {
            let guard = self.token.read().await;
            if Instant::now() + Duration::from_secs(EXPIRY_BUFFER_SECS) < guard.expires_at {
                return Ok(guard.access_token.clone());
            }
        }

        let mut guard = self.token.write().await;
        if Instant::now() + Duration::from_secs(EXPIRY_BUFFER_SECS) < guard.expires_at {
            return Ok(guard.access_token.clone());
        }

        match exchange_jwt_assertion(
            &self.token_url,
            &self.jwt_source,
            &self.assertion_audience,
            &self.extra_params,
            &self.tls_connector,
        )
        .await
        {
            Ok((new_token, expires_in, _)) => {
                debug!(
                    "OAuth2 jwt-bearer token refreshed, expires in {}s",
                    expires_in.as_secs()
                );
                guard.access_token = new_token;
                guard.expires_at = Instant::now() + expires_in;
                Ok(guard.access_token.clone())
            }
            // SVID fetch failed — workload identity is gone; fail the request.
            Err(e @ ProxyError::Credential(_)) => Err(e),
            // Token exchange failed (network/auth) — use stale token if available.
            Err(e) => {
                warn!(
                    "OAuth2 jwt-bearer token refresh failed, returning stale token: {}",
                    e
                );
                Ok(guard.access_token.clone())
            }
        }
    }
}

async fn exchange_jwt_assertion(
    token_url: &str,
    jwt_source: &crate::spiffe::SpiffeJwtSource,
    audience: &[String],
    extra_params: &[(String, String)],
    tls_connector: &TlsConnector,
) -> Result<(Zeroizing<String>, Duration, String)> {
    let (assertion, spiffe_id) = jwt_source.fetch_token(audience).await?;

    let mut body = Zeroizing::new(format!(
        "grant_type={}&client_assertion_type={}&assertion={}",
        urlencoding::encode("urn:ietf:params:oauth:grant-type:jwt-bearer"),
        urlencoding::encode("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
        urlencoding::encode(assertion.as_str()),
    ));
    for (k, v) in extra_params {
        body.push_str(&format!(
            "&{}={}",
            urlencoding::encode(k),
            urlencoding::encode(v)
        ));
    }

    let parsed = url::Url::parse(token_url)
        .map_err(|e| ProxyError::OAuth2Exchange(format!("invalid token_url '{token_url}': {e}")))?;

    let scheme = parsed.scheme();
    let is_https = match scheme {
        "https" => true,
        "http" => {
            let is_loopback = parsed.host_str().is_some_and(|h| {
                h == "localhost"
                    || h.parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            });
            if !is_loopback {
                return Err(ProxyError::OAuth2Exchange(format!(
                    "token_url '{token_url}' must use https:// (http:// only allowed for loopback)"
                )));
            }
            false
        }
        other => {
            return Err(ProxyError::OAuth2Exchange(format!(
                "unsupported scheme '{other}' in token_url"
            )));
        }
    };

    let host = parsed
        .host_str()
        .ok_or_else(|| {
            ProxyError::OAuth2Exchange(format!("missing host in token_url '{token_url}'"))
        })?
        .to_string();
    let port = parsed.port().unwrap_or(if is_https { 443 } else { 80 });
    let path_with_query = token_request_target(&parsed);

    let request = Zeroizing::new(format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n{}",
        path_with_query,
        host,
        body.len(),
        body.as_str()
    ));

    let addr = format!("{}:{}", host, port);
    let response = tokio::time::timeout(EXCHANGE_TIMEOUT, async {
        let tcp = TcpStream::connect(&addr)
            .await
            .map_err(|e| ProxyError::OAuth2Exchange(format!("TCP connect to {addr}: {e}")))?;

        async fn send_and_read<S: tokio::io::AsyncWrite + tokio::io::AsyncRead + Unpin>(
            stream: &mut S,
            request: &[u8],
            host: &str,
        ) -> Result<TokenHttpResponse> {
            stream
                .write_all(request)
                .await
                .map_err(|e| ProxyError::OAuth2Exchange(format!("write to {host}: {e}")))?;
            stream
                .flush()
                .await
                .map_err(|e| ProxyError::OAuth2Exchange(format!("flush to {host}: {e}")))?;
            read_http_response(stream).await
        }

        if is_https {
            let server_name =
                rustls::pki_types::ServerName::try_from(host.clone()).map_err(|_| {
                    ProxyError::OAuth2Exchange(format!("invalid TLS server name: {host}"))
                })?;
            let mut tls = tls_connector.connect(server_name, tcp).await.map_err(|e| {
                ProxyError::OAuth2Exchange(format!("TLS handshake with {host}: {e}"))
            })?;
            send_and_read(&mut tls, request.as_bytes(), &host).await
        } else {
            let mut tcp = tcp;
            send_and_read(&mut tcp, request.as_bytes(), &host).await
        }
    })
    .await
    .map_err(|_| ProxyError::OAuth2Exchange(format!("token exchange with {addr} timed out")))??;

    if !(200..300).contains(&response.status) {
        let preview: String = response.body.chars().take(200).collect();
        return Err(ProxyError::OAuth2Exchange(format!(
            "token endpoint returned HTTP {}: {preview}",
            response.status
        )));
    }
    let (token, expires) = parse_token_response(&response.body)?;
    Ok((token, expires, spiffe_id))
}

/// Decode an HTTP/1.1 chunked body.
///
/// Returns `Ok(None)` while the body is incomplete (no terminal chunk and
/// empty trailer line yet), and an error for malformed framing.
fn decode_chunked(body: &[u8]) -> Result<Option<Vec<u8>>> {
    let malformed = || ProxyError::OAuth2Exchange("malformed chunked token response".to_string());
    let find_crlf = |from: usize| {
        body[from..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .map(|i| from + i)
    };

    let mut out = Vec::with_capacity(body.len());
    let mut pos = 0;
    loop {
        let Some(line_end) = find_crlf(pos) else {
            return Ok(None);
        };
        let size_line = std::str::from_utf8(&body[pos..line_end]).map_err(|_| malformed())?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        if size_hex.is_empty() || !size_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(malformed());
        }
        let size = usize::from_str_radix(size_hex, 16).map_err(|_| malformed())?;
        pos = line_end + 2;
        if size == 0 {
            break;
        }
        let data_end = pos.checked_add(size).ok_or_else(malformed)?;
        let chunk_end = data_end.checked_add(2).ok_or_else(malformed)?;
        if body.len() < chunk_end {
            return Ok(None);
        }
        if &body[data_end..chunk_end] != b"\r\n" {
            return Err(malformed());
        }
        out.extend_from_slice(&body[pos..data_end]);
        pos = chunk_end;
    }

    // Trailer section: zero or more header lines, then an empty line.
    loop {
        let Some(line_end) = find_crlf(pos) else {
            return Ok(None);
        };
        let is_empty = line_end == pos;
        pos = line_end + 2;
        if is_empty {
            return Ok(Some(out));
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader};

    const FAKE_TOKEN_JSON: &str =
        r#"{"access_token":"fake-token","token_type":"Bearer","expires_in":3600}"#;

    // ── exchange_token response framing ──────────────────────────────────

    #[tokio::test]
    async fn test_exchange_token_chunked_response() {
        // A numeric first chunk-size line reproduces the reported JSON error
        // (trailing characters at line 2 column 1) without HTTP decoding.
        let (first, second) = FAKE_TOKEN_JSON.split_at(16);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
             Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
             {:x}\r\n{}\r\n{:x}\r\n{}\r\n0\r\n\r\n",
            first.len(),
            first,
            second.len(),
            second
        );
        let (token, expires) = exchange_mock_token_response(response).await.unwrap();
        assert!(token.as_str() == "fake-token");
        assert_eq!(expires, Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn test_exchange_token_content_length_response() {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            FAKE_TOKEN_JSON.len(),
            FAKE_TOKEN_JSON
        );
        let (token, expires) = exchange_mock_token_response(response).await.unwrap();
        assert!(token.as_str() == "fake-token");
        assert_eq!(expires, Duration::from_secs(3600));
    }

    // ── read_http_response framing ───────────────────────────────────────

    /// Yields `data`, then fails like rustls does when a peer closes without
    /// sending `close_notify`.
    struct NoCloseNotifyReader {
        data: Vec<u8>,
        pos: usize,
    }

    impl NoCloseNotifyReader {
        fn new(data: &str) -> Self {
            Self {
                data: data.as_bytes().to_vec(),
                pos: 0,
            }
        }
    }

    impl tokio::io::AsyncRead for NoCloseNotifyReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            let this = self.get_mut();
            if this.pos >= this.data.len() {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "peer closed connection without sending TLS close_notify",
                )));
            }
            let n = buf.remaining().min(this.data.len() - this.pos);
            buf.put_slice(&this.data[this.pos..this.pos + n]);
            this.pos += n;
            std::task::Poll::Ready(Ok(()))
        }
    }

    fn content_length_response(body: &str) -> String {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
    }

    fn chunked_response(body: &str) -> String {
        let (first, second) = body.split_at(body.len() / 2);
        format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
             {:x}\r\n{}\r\n{:x};ext=1\r\n{}\r\n0\r\n\r\n",
            first.len(),
            first,
            second.len(),
            second
        )
    }

    #[tokio::test]
    async fn read_http_response_content_length_without_close_notify() {
        let mut stream = NoCloseNotifyReader::new(&content_length_response(FAKE_TOKEN_JSON));
        let response = read_http_response(&mut stream).await.unwrap();
        assert_eq!(response.status, 200);
        assert!(response.body.as_str() == FAKE_TOKEN_JSON);
    }

    #[tokio::test]
    async fn read_http_response_chunked_without_close_notify() {
        let mut stream = NoCloseNotifyReader::new(&chunked_response(FAKE_TOKEN_JSON));
        let response = read_http_response(&mut stream).await.unwrap();
        assert_eq!(response.status, 200);
        assert!(response.body.as_str() == FAKE_TOKEN_JSON);
    }

    #[tokio::test]
    async fn read_http_response_chunked_with_trailers() {
        let raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                   2\r\n{}\r\n0\r\nX-Trailer: 1\r\n\r\n";
        let mut stream = NoCloseNotifyReader::new(raw);
        let response = read_http_response(&mut stream).await.unwrap();
        assert!(response.body.as_str() == "{}");
    }

    #[tokio::test]
    async fn read_http_response_short_content_length_errors() {
        let full = content_length_response(FAKE_TOKEN_JSON);
        let truncated = &full[..full.len() - 5];

        let err = read_http_response(&mut truncated.as_bytes())
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("truncated token response"));

        let err = read_http_response(&mut NoCloseNotifyReader::new(truncated))
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("close_notify"));
    }

    #[tokio::test]
    async fn read_http_response_missing_terminal_chunk_errors() {
        let full = chunked_response(FAKE_TOKEN_JSON);
        let truncated = full.strip_suffix("0\r\n\r\n").unwrap();

        let err = read_http_response(&mut truncated.as_bytes())
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("truncated token response"));

        let err = read_http_response(&mut NoCloseNotifyReader::new(truncated))
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("close_notify"));
    }

    #[tokio::test]
    async fn read_http_response_malformed_chunk_errors() {
        let raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                   zz\r\n{}\r\n0\r\n\r\n";
        let err = read_http_response(&mut raw.as_bytes()).await.err().unwrap();
        assert!(err.to_string().contains("malformed chunked"));
    }

    #[tokio::test]
    async fn read_http_response_unframed_reads_to_clean_eof() {
        let raw = format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{FAKE_TOKEN_JSON}");
        let response = read_http_response(&mut raw.as_bytes()).await.unwrap();
        assert!(response.body.as_str() == FAKE_TOKEN_JSON);
    }

    #[tokio::test]
    async fn read_http_response_unframed_without_close_notify_errors() {
        let raw = format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{FAKE_TOKEN_JSON}");
        let err = read_http_response(&mut NoCloseNotifyReader::new(&raw))
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("close_notify"));
    }

    #[tokio::test]
    async fn read_http_response_oversized_errors() {
        let declared = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_TOKEN_RESPONSE
        );
        let err = read_http_response(&mut declared.as_bytes())
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("exceeds"));

        let body = "a".repeat(MAX_TOKEN_RESPONSE + 1);
        let raw = format!("HTTP/1.1 200 OK\r\n\r\n{body}");
        let err = read_http_response(&mut raw.as_bytes()).await.err().unwrap();
        assert!(err.to_string().contains("exceeds"));
    }

    // ── parse_token_response ─────────────────────────────────────────────

    #[test]
    fn test_parse_token_response_success() {
        let json =
            r#"{"access_token":"eyJhbGciOiJSUzI1NiJ9","token_type":"Bearer","expires_in":3600}"#;
        let (token, expires) = parse_token_response(json).unwrap();
        assert_eq!(token.as_str(), "eyJhbGciOiJSUzI1NiJ9");
        assert_eq!(expires, Duration::from_secs(3600));
    }

    #[test]
    fn test_parse_token_response_missing_expires_defaults() {
        let json = r#"{"access_token":"tok_abc","token_type":"Bearer"}"#;
        let (token, expires) = parse_token_response(json).unwrap();
        assert_eq!(token.as_str(), "tok_abc");
        assert_eq!(expires, Duration::from_secs(DEFAULT_EXPIRES_IN_SECS));
    }

    #[test]
    fn test_parse_token_response_missing_access_token_errors() {
        let json = r#"{"token_type":"Bearer","expires_in":3600}"#;
        let err = parse_token_response(json).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("access_token"),
            "error should mention access_token: {}",
            msg
        );
    }

    #[test]
    fn test_parse_token_response_non_json_errors() {
        let err = parse_token_response("this is not json").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("invalid JSON"),
            "error should mention invalid JSON: {}",
            msg
        );
    }

    // ── build_token_request_body ─────────────────────────────────────────

    #[test]
    fn test_build_token_request_body() {
        let body = build_token_request_body("my-client", "s3cret!", "read write");
        assert!(body.contains("grant_type=client_credentials"));
        assert!(body.contains("client_id=my-client"));
        assert!(body.contains("client_secret=s3cret%21"));
        assert!(body.contains("scope=read%20write"));
    }

    #[test]
    fn test_build_token_request_body_no_scope() {
        let body = build_token_request_body("cid", "csec", "");
        assert!(body.contains("grant_type=client_credentials"));
        assert!(body.contains("client_id=cid"));
        assert!(body.contains("client_secret=csec"));
        assert!(!body.contains("scope="), "empty scope should be omitted");
    }

    // ── parse_status_code ────────────────────────────────────────────────

    #[test]
    fn test_parse_status_code_200() {
        assert_eq!(parse_status_code("HTTP/1.1 200 OK"), 200);
    }

    #[test]
    fn test_parse_status_code_401() {
        assert_eq!(parse_status_code("HTTP/1.1 401 Unauthorized"), 401);
    }

    #[test]
    fn test_parse_status_code_garbage() {
        assert_eq!(parse_status_code("not http"), 0);
    }

    #[test]
    fn token_request_target_keeps_query_string() {
        let parsed =
            url::Url::parse("https://auth.example.com/oauth/token?api-version=2024-01-01").unwrap();
        assert_eq!(
            token_request_target(&parsed),
            "/oauth/token?api-version=2024-01-01"
        );
    }

    #[test]
    fn token_request_target_without_query_is_path() {
        let parsed = url::Url::parse("https://auth.example.com/oauth/token").unwrap();
        assert_eq!(token_request_target(&parsed), "/oauth/token");
    }

    // ── TokenCache expiry logic ──────────────────────────────────────────

    #[tokio::test]
    async fn test_token_cache_returns_valid_token() {
        // Construct a cache with a token that expires far in the future.
        let cache = make_test_cache("valid_token", Duration::from_secs(3600));
        let token = cache.get_or_refresh().await;
        assert_eq!(token.as_str(), "valid_token");
    }

    #[tokio::test]
    async fn test_token_cache_detects_expiry() {
        // Token that "expired" 10 seconds ago. Because exchange_token will
        // fail (no real server), the stale token is returned.
        let cache = make_test_cache("stale_token", Duration::from_secs(0));
        // Manually set expires_at to the past.
        {
            let mut guard = cache.token.write().await;
            guard.expires_at = Instant::now() - Duration::from_secs(10);
        }
        let token = cache.get_or_refresh().await;
        // Should still get the stale token (graceful degradation).
        assert_eq!(token.as_str(), "stale_token");
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    /// Exercise the real exchange against a loopback server using only fake
    /// credentials. Consume the request before responding, without logging it.
    async fn exchange_mock_token_response(
        response: String,
    ) -> Result<(Zeroizing<String>, Duration)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(5), async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut reader = BufReader::new(stream);
                loop {
                    let mut line = String::new();
                    assert!(reader.read_line(&mut line).await.unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                }
                let expected_body =
                    b"grant_type=client_credentials&client_id=test-client&client_secret=test-secret";
                let mut body = vec![0; expected_body.len()];
                reader.read_exact(&mut body).await.unwrap();
                assert!(body == expected_body);
                reader.get_mut().write_all(response.as_bytes()).await.unwrap();
                reader.get_mut().shutdown().await.unwrap();
            })
            .await
            .unwrap();
        });
        let config = OAuth2ExchangeConfig {
            token_url: format!("http://{addr}/oauth/token"),
            client_id: Zeroizing::new("test-client".to_string()),
            client_secret: Zeroizing::new("test-secret".to_string()),
            scope: String::new(),
        };
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            exchange_token(&config, &make_test_tls_connector()),
        )
        .await
        .unwrap();
        server.await.unwrap();
        result
    }

    /// Build a `TokenCache` with a pre-populated token for unit tests.
    /// The `exchange_token` config points to a non-routable address so any
    /// actual exchange attempt will fail (which is fine — we test cache logic).
    fn make_test_cache(token: &str, ttl: Duration) -> TokenCache {
        let config = OAuth2ExchangeConfig {
            token_url: "https://127.0.0.1:1/oauth/token".to_string(),
            client_id: Zeroizing::new("test-client".to_string()),
            client_secret: Zeroizing::new("test-secret".to_string()),
            scope: String::new(),
        };

        TokenCache::new_from_parts(config, make_test_tls_connector(), token, ttl)
    }

    // The mock endpoint uses loopback HTTP, so this connector never sends secrets.
    fn make_test_tls_connector() -> TlsConnector {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();
        TlsConnector::from(Arc::new(tls_config))
    }
}
