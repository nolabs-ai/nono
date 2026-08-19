//! Bounded line reading shared by proxy paths that read untrusted
//! line-oriented data (request/status lines, headers, chunk-size and trailer
//! lines) from a client, upstream, or external proxy socket. Without a bound,
//! a peer that never sends a newline can make `read_line` grow its buffer
//! without limit and OOM the proxy.

use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// Cap on a single line read via [`read_line_limited`] / [`read_line_limited_string`].
pub(crate) const MAX_LINE_SIZE: usize = 8 * 1024;

/// Read one line from `reader`, erroring once `max_len` bytes buffer without a
/// newline. `Ok(None)` on clean EOF; otherwise mirrors `read_line`'s semantics.
pub(crate) async fn read_line_limited<R>(
    reader: &mut R,
    max_len: usize,
) -> std::io::Result<Option<Vec<u8>>>
where
    R: AsyncBufRead + Unpin,
{
    let mut buf = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok((!buf.is_empty()).then_some(buf));
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            if buf.len().saturating_add(pos).saturating_add(1) > max_len {
                reader.consume(pos + 1);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "line exceeded maximum length",
                ));
            }
            buf.extend_from_slice(&available[..=pos]);
            reader.consume(pos + 1);
            return Ok(Some(buf));
        }
        if buf.len().saturating_add(available.len()) > max_len {
            let consumed = available.len();
            reader.consume(consumed);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "line exceeded maximum length",
            ));
        }
        let consumed = available.len();
        buf.extend_from_slice(available);
        reader.consume(consumed);
    }
}

/// String-returning wrapper matching `AsyncBufReadExt::read_line`'s calling
/// convention (appends to `buf`, returns bytes read, 0 means EOF), for call
/// sites that parse the line as UTF-8 text.
pub(crate) async fn read_line_limited_string<R>(
    reader: &mut R,
    buf: &mut String,
    max_len: usize,
) -> std::io::Result<usize>
where
    R: AsyncBufRead + Unpin,
{
    match read_line_limited(reader, max_len).await? {
        None => Ok(0),
        Some(bytes) => {
            let len = bytes.len();
            let text = String::from_utf8(bytes).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "line is not valid UTF-8")
            })?;
            buf.push_str(&text);
            Ok(len)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, BufReader};

    #[tokio::test]
    async fn read_line_limited_returns_none_on_clean_eof() {
        let (client, server) = tokio::io::duplex(64);
        drop(client);
        let mut reader = BufReader::new(server);
        assert_eq!(read_line_limited(&mut reader, 64).await.unwrap(), None);
    }

    #[tokio::test]
    async fn read_line_limited_rejects_line_over_max_len_without_newline() {
        let (mut client, server) = tokio::io::duplex(MAX_LINE_SIZE * 2);
        let mut reader = BufReader::new(server);
        client
            .write_all(&vec![b'a'; MAX_LINE_SIZE + 1])
            .await
            .unwrap();
        let result = read_line_limited(&mut reader, MAX_LINE_SIZE).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn read_line_limited_string_returns_zero_on_clean_eof() {
        let (client, server) = tokio::io::duplex(64);
        drop(client);
        let mut reader = BufReader::new(server);
        let mut buf = String::new();
        assert_eq!(
            read_line_limited_string(&mut reader, &mut buf, 64)
                .await
                .unwrap(),
            0
        );
        assert!(buf.is_empty());
    }

    #[tokio::test]
    async fn read_line_limited_string_reads_a_line() {
        let (mut client, server) = tokio::io::duplex(64);
        client.write_all(b"hello\r\n").await.unwrap();
        let mut reader = BufReader::new(server);
        let mut buf = String::new();
        let n = read_line_limited_string(&mut reader, &mut buf, 64)
            .await
            .unwrap();
        assert_eq!(n, 7);
        assert_eq!(buf, "hello\r\n");
    }

    #[tokio::test]
    async fn read_line_limited_string_rejects_invalid_utf8() {
        let (mut client, server) = tokio::io::duplex(64);
        client.write_all(&[0xff, 0xfe, b'\n']).await.unwrap();
        let mut reader = BufReader::new(server);
        let mut buf = String::new();
        assert!(
            read_line_limited_string(&mut reader, &mut buf, 64)
                .await
                .is_err()
        );
    }
}
