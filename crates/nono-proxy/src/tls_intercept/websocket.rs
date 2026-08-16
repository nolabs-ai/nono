//! WebSocket handshake parsing for authenticated TLS-intercept tunnels.

use super::http1::{self, HeaderField};
use crate::error::{ProxyError, Result};
use crate::reverse;
use base64::Engine as _;
use sha1::{Digest, Sha1};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

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
        let mut status_line = String::new();
        if reader.read_line(&mut status_line).await? == 0 {
            return Err(ProxyError::UpstreamConnect {
                host: host.to_string(),
                reason: "upstream closed before sending an upgrade response".to_string(),
            });
        }
        let status = parse_status_line(&status_line)?;
        let mut header_bytes = Vec::new();
        loop {
            let mut line = String::new();
            let count = reader.read_line(&mut line).await?;
            if count == 0 {
                return Err(ProxyError::UpstreamConnect {
                    host: host.to_string(),
                    reason: "upstream closed before terminating upgrade response headers"
                        .to_string(),
                });
            }
            if line == "\r\n" || line == "\n" {
                break;
            }
            header_bytes.extend_from_slice(line.as_bytes());
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
