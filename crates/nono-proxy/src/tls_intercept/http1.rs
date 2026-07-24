//! Strict HTTP/1 head parsing and single-response framing for TLS interception.

use crate::error::{ProxyError, Result};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

const MAX_RESPONSE_BODY: u64 = 16 * 1024 * 1024;
const RESPONSE_BODY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HeaderField {
    pub name: String,
    pub value: String,
}

pub(crate) fn parse_header_fields(bytes: &[u8]) -> Result<Vec<HeaderField>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ProxyError::HttpParse("HTTP headers are not UTF-8".to_string()))?;
    let mut fields = Vec::new();
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        if line.starts_with([' ', '\t']) {
            return Err(ProxyError::HttpParse(
                "obsolete folded HTTP header is not permitted".to_string(),
            ));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| ProxyError::HttpParse("malformed HTTP header".to_string()))?;
        if name.is_empty()
            || name.trim() != name
            || !name.bytes().all(is_header_name_byte)
            || value.bytes().any(|byte| byte == 0)
        {
            return Err(ProxyError::HttpParse(
                "invalid HTTP header name or value".to_string(),
            ));
        }
        fields.push(HeaderField {
            name: name.to_ascii_lowercase(),
            value: value.trim().to_string(),
        });
    }
    Ok(fields)
}

fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

pub(crate) fn values<'a>(fields: &'a [HeaderField], name: &str) -> Vec<&'a str> {
    fields
        .iter()
        .filter(|field| field.name.eq_ignore_ascii_case(name))
        .map(|field| field.value.as_str())
        .collect()
}

pub(crate) fn filter_websocket_request(
    fields: &[HeaderField],
    credential_headers: &[String],
) -> Vec<HeaderField> {
    fields
        .iter()
        .filter(|field| {
            !matches!(
                field.name.as_str(),
                "host" | "content-length" | "proxy-connection" | "proxy-authorization"
            ) && !credential_headers
                .iter()
                .any(|name| field.name.eq_ignore_ascii_case(name))
        })
        .cloned()
        .collect()
}

enum BodyFraming {
    Empty,
    ContentLength(u64),
    Chunked,
    CloseDelimited,
}

fn response_body_framing(status: u16, fields: &[HeaderField]) -> Result<BodyFraming> {
    if (100..200).contains(&status) || matches!(status, 204 | 304) {
        return Ok(BodyFraming::Empty);
    }
    let transfer = values(fields, "transfer-encoding");
    if transfer
        .iter()
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("chunked"))
    {
        return Ok(BodyFraming::Chunked);
    }
    let lengths = values(fields, "content-length");
    match lengths.as_slice() {
        [] => Ok(BodyFraming::CloseDelimited),
        [value] => {
            let length = value.parse::<u64>().map_err(|_| {
                ProxyError::HttpParse("invalid upstream Content-Length".to_string())
            })?;
            if length > MAX_RESPONSE_BODY {
                return Err(ProxyError::HttpParse(
                    "upstream response body exceeds size limit".to_string(),
                ));
            }
            Ok(BodyFraming::ContentLength(length))
        }
        _ => Err(ProxyError::HttpParse(
            "duplicate upstream Content-Length".to_string(),
        )),
    }
}

pub(crate) async fn relay_response_body<U, C>(
    upstream: &mut U,
    client: &mut C,
    status: u16,
    fields: &[HeaderField],
    leftover: Vec<u8>,
) -> Result<()>
where
    U: AsyncRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let framing = response_body_framing(status, fields)?;
    let relay = async {
        let prefix = std::io::Cursor::new(leftover);
        let chained = prefix.chain(&mut *upstream);
        let mut reader = BufReader::new(chained);
        match framing {
            BodyFraming::Empty => {}
            BodyFraming::ContentLength(length) => {
                let copied = tokio::io::copy(&mut reader.take(length), client).await?;
                if copied != length {
                    return Err(ProxyError::HttpParse(
                        "upstream closed before Content-Length body completed".to_string(),
                    ));
                }
            }
            BodyFraming::Chunked => relay_chunked(&mut reader, client).await?,
            BodyFraming::CloseDelimited => {
                let copied =
                    tokio::io::copy(&mut reader.take(MAX_RESPONSE_BODY + 1), client).await?;
                if copied > MAX_RESPONSE_BODY {
                    return Err(ProxyError::HttpParse(
                        "upstream close-delimited response exceeds size limit".to_string(),
                    ));
                }
            }
        }
        client.flush().await?;
        Ok(())
    };
    tokio::time::timeout(RESPONSE_BODY_TIMEOUT, relay)
        .await
        .map_err(|_| {
            ProxyError::HttpParse("timed out relaying upstream response body".to_string())
        })?
}

async fn relay_chunked<R, C>(reader: &mut R, client: &mut C) -> Result<()>
where
    R: tokio::io::AsyncBufRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let mut total = 0u64;
    loop {
        let mut size_line = String::new();
        if reader.read_line(&mut size_line).await? == 0 {
            return Err(ProxyError::HttpParse(
                "truncated chunked response".to_string(),
            ));
        }
        client.write_all(size_line.as_bytes()).await?;
        let size_text = size_line.trim_end().split(';').next().unwrap_or("");
        let size = u64::from_str_radix(size_text.trim(), 16)
            .map_err(|_| ProxyError::HttpParse("invalid chunk size".to_string()))?;
        total = total
            .checked_add(size)
            .ok_or_else(|| ProxyError::HttpParse("chunked response size overflow".to_string()))?;
        if total > MAX_RESPONSE_BODY {
            return Err(ProxyError::HttpParse(
                "chunked response exceeds size limit".to_string(),
            ));
        }
        if size > 0 {
            let copied = tokio::io::copy(&mut reader.take(size + 2), client).await?;
            if copied != size + 2 {
                return Err(ProxyError::HttpParse(
                    "truncated chunked response".to_string(),
                ));
            }
            continue;
        }
        loop {
            let mut trailer = String::new();
            if reader.read_line(&mut trailer).await? == 0 {
                return Err(ProxyError::HttpParse(
                    "truncated chunked trailers".to_string(),
                ));
            }
            client.write_all(trailer.as_bytes()).await?;
            if trailer == "\r\n" || trailer == "\n" {
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn strict_parser_rejects_whitespace_before_colon() {
        assert!(parse_header_fields(b"Host : attacker.example\r\n").is_err());
    }

    #[test]
    fn websocket_filter_strips_authority_and_credentials_by_parsed_name() {
        let fields = parse_header_fields(
            b"Host: example.com\r\nAuthorization: phantom\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n",
        )
        .unwrap();
        let filtered = filter_websocket_request(&fields, &["authorization".to_string()]);
        assert_eq!(
            filtered,
            vec![
                HeaderField {
                    name: "connection".to_string(),
                    value: "Upgrade".to_string(),
                },
                HeaderField {
                    name: "upgrade".to_string(),
                    value: "websocket".to_string(),
                },
            ]
        );
    }

    #[tokio::test]
    async fn content_length_relay_finishes_without_waiting_for_eof() {
        let (mut upstream_client, mut upstream_server) = tokio::io::duplex(64);
        let fields = parse_header_fields(b"Content-Length: 4\r\n").unwrap();
        let writer = tokio::spawn(async move {
            upstream_client.write_all(b"body").await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let (mut output_client, mut output_server) = tokio::io::duplex(64);
        relay_response_body(
            &mut upstream_server,
            &mut output_client,
            403,
            &fields,
            Vec::new(),
        )
        .await
        .unwrap();
        drop(output_client);
        let mut output = Vec::new();
        output_server.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, b"body");
        writer.abort();
    }
}
