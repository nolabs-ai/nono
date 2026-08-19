//! WebSocket handshake parsing for authenticated TLS-intercept tunnels.

use super::http1::{self, HeaderField};
use crate::error::{ProxyError, Result};
use crate::line_reader::{MAX_LINE_SIZE, read_line_limited};
use crate::reverse;
use base64::Engine as _;
use sha1::{Digest, Sha1};
use std::time::Duration;
use tokio::io::{AsyncRead, BufReader};

const MAX_HEADER_SIZE: usize = 64 * 1024;
const UPSTREAM_HEADER_TIMEOUT: Duration = Duration::from_secs(30);

/// RFC 6455 section 1.3: fixed GUID concatenated with the client's
/// `Sec-WebSocket-Key` before hashing to derive `Sec-WebSocket-Accept`.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Compute the expected `Sec-WebSocket-Accept` value for a given client
/// `Sec-WebSocket-Key`, per RFC 6455 section 1.3 (SHA-1 of key+GUID, base64).
pub(crate) fn expected_accept(client_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(client_key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
}

pub(crate) struct HandshakeResponse {
    pub status: u16,
    pub status_line_raw: String,
    pub header_bytes: Vec<u8>,
    pub header_fields: Vec<HeaderField>,
    pub leftover: Vec<u8>,
}

pub(crate) async fn read_response<U>(upstream: &mut U, host: &str) -> Result<HandshakeResponse>
where
    U: AsyncRead + Unpin,
{
    let read = async {
        let mut reader = BufReader::new(&mut *upstream);
        let status_line_bytes = read_line_limited(&mut reader, MAX_LINE_SIZE)
            .await?
            .ok_or_else(|| ProxyError::UpstreamConnect {
                host: host.to_string(),
                reason: "upstream closed before sending an upgrade response".to_string(),
            })?;
        let status_line = String::from_utf8(status_line_bytes).map_err(|_| {
            ProxyError::HttpParse("malformed upstream status line: invalid UTF-8".to_string())
        })?;
        let status = parse_status_line(&status_line)?;
        let mut header_bytes = Vec::new();
        loop {
            let line = read_line_limited(&mut reader, MAX_LINE_SIZE)
                .await?
                .ok_or_else(|| ProxyError::UpstreamConnect {
                    host: host.to_string(),
                    reason: "upstream closed before terminating upgrade response headers"
                        .to_string(),
                })?;
            if line == b"\r\n" || line == b"\n" {
                break;
            }
            header_bytes.extend_from_slice(&line);
            if header_bytes.len() > MAX_HEADER_SIZE {
                return Err(ProxyError::UpstreamConnect {
                    host: host.to_string(),
                    reason: "upstream upgrade response headers exceeded size limit".to_string(),
                });
            }
        }
        let header_fields = http1::parse_header_fields(&header_bytes)?;
        Ok(HandshakeResponse {
            status,
            status_line_raw: status_line,
            header_bytes,
            header_fields,
            leftover: reader.buffer().to_vec(),
        })
    };
    tokio::time::timeout(UPSTREAM_HEADER_TIMEOUT, read)
        .await
        .map_err(|_| ProxyError::UpstreamConnect {
            host: host.to_string(),
            reason: "timed out waiting for upstream upgrade response".to_string(),
        })?
}

pub(crate) fn parse_status_line(line: &str) -> Result<u16> {
    let mut parts = line.split_whitespace();
    if parts.next() != Some("HTTP/1.1") {
        return Err(ProxyError::HttpParse(format!(
            "malformed upstream status line: {line}"
        )));
    }
    let code = parts
        .next()
        .ok_or_else(|| ProxyError::HttpParse(format!("malformed upstream status line: {line}")))?;
    if code.len() != 3 {
        return Err(ProxyError::HttpParse(format!(
            "malformed upstream status code: {code}"
        )));
    }
    code.parse::<u16>()
        .map_err(|_| ProxyError::HttpParse(format!("malformed upstream status code: {code}")))
}

pub(crate) fn is_valid_response(status: u16, header_bytes: &[u8], client_key: &str) -> bool {
    let Ok(fields) = http1::parse_header_fields(header_bytes) else {
        return false;
    };
    let expected = expected_accept(client_key);
    status == 101
        && http1::values(&fields, "connection")
            .iter()
            .any(|value| reverse::connection_has_upgrade_token(value))
        && http1::values(&fields, "upgrade")
            .iter()
            .any(|value| value.eq_ignore_ascii_case("websocket"))
        && matches!(http1::values(&fields, "sec-websocket-accept").as_slice(), [accept] if *accept == expected)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    // Regression test: an upstream that never terminates the status line must
    // be rejected immediately by the per-line size cap, not left to grow an
    // unbounded buffer until the 30s connect timeout (or OOM) kicks in.
    #[tokio::test]
    async fn read_response_rejects_unterminated_status_line() {
        let (mut client, server) = tokio::io::duplex(MAX_LINE_SIZE * 2);
        client
            .write_all(&vec![b'a'; MAX_LINE_SIZE + 1])
            .await
            .unwrap();
        client.flush().await.unwrap();

        let mut server = server;
        let result = read_response(&mut server, "example.com").await;
        assert!(result.is_err());
    }

    // Regression test: a single header line with no terminator that exceeds
    // the per-line cap must be rejected without buffering it in full, even
    // though it's still under the cumulative MAX_HEADER_SIZE budget.
    #[tokio::test]
    async fn read_response_rejects_unterminated_header_line() {
        let (mut client, server) = tokio::io::duplex(MAX_LINE_SIZE * 2);
        client
            .write_all(b"HTTP/1.1 101 Switching Protocols\r\n")
            .await
            .unwrap();
        client
            .write_all(&vec![b'a'; MAX_LINE_SIZE + 1])
            .await
            .unwrap();
        client.flush().await.unwrap();

        let mut server = server;
        let result = read_response(&mut server, "example.com").await;
        assert!(result.is_err());
    }

    // An oversized line whose `\n` lands in the same `fill_buf` chunk must still
    // be rejected: capping only the no-newline branch would let it through.
    #[tokio::test]
    async fn read_line_limited_rejects_newline_terminated_line_over_max_len() {
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(b"aaaaaaaaaa\n").await.unwrap();
        client.flush().await.unwrap();
        drop(client);

        let mut reader = BufReader::new(server);
        let result = read_line_limited(&mut reader, 5).await;
        assert!(result.is_err());
    }
}
