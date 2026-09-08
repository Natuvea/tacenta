//! One HTTP `GET`, for fetching a server's service document.
//!
//! This is not an HTTP client. It speaks exactly enough HTTP/1.1 to fetch one
//! small JSON document from a known server: a request with `Connection:
//! close`, a status line, headers, and a body framed by `Content-Length`, by
//! chunked encoding, or by the close. Nothing else: no redirects, no
//! keep-alive, no compression, no authentication. A full HTTP client is a
//! large dependency, and the only thing the client crate needs from HTTP is
//! this one round trip (decision 0090), over the same TLS trust the
//! four framed services already use.
//!
//! The body is read to its framing, not to the close: a server that keeps the
//! socket open after a sized body does not stall the fetch, and a TLS peer
//! that closes without a `close_notify` after a complete body is not an
//! error. The whole exchange is bounded by a deadline, and the body by 64 KiB.
//! A service document is a few hundred bytes, and a server that answers with
//! more is not the server we were looking for.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::ClientTls;

/// The most bytes accepted in a response body.
const MAX_BODY: usize = 64 * 1024;

/// The most bytes accepted in the status line and headers.
const MAX_HEAD: usize = 16 * 1024;

/// How long one fetch may take, connect to last byte.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);

use crate::url::Target;

fn invalid(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, m.to_owned())
}

fn bad(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m.to_owned())
}

fn parse(url: &str) -> io::Result<Target> {
    let target = Target::parse(url)?;
    if !matches!(target.scheme.as_str(), "http" | "https") {
        return Err(invalid("url must start with http:// or https://"));
    }
    Ok(target)
}

/// Fetch `url` and return the response body, within [`DEFAULT_TIMEOUT`].
/// `tls` decides the trust for an `https://` URL and is unused for
/// `http://`. Any status other than `200` is an error carrying the status
/// line.
pub async fn get(url: &str, tls: &ClientTls) -> io::Result<Vec<u8>> {
    get_within(url, tls, DEFAULT_TIMEOUT).await
}

/// [`get`] with an explicit deadline for the whole exchange.
pub async fn get_within(url: &str, tls: &ClientTls, timeout: Duration) -> io::Result<Vec<u8>> {
    let target = parse(url)?;
    tokio::time::timeout(timeout, fetch(&target, tls))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!("no complete response within {timeout:?}"),
            )
        })?
}

async fn fetch(target: &Target, tls: &ClientTls) -> io::Result<Vec<u8>> {
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nUser-Agent: tacenta-client\r\nConnection: close\r\n\r\n",
        target.path, target.authority
    );
    let tcp = TcpStream::connect((target.host.as_str(), target.port)).await?;
    if target.tls {
        let stream = tls.wrap(&target.host, tcp).await?;
        exchange(stream, request.as_bytes()).await
    } else {
        exchange(tcp, request.as_bytes()).await
    }
}

/// How the body ends.
enum Framing {
    Length(usize),
    Chunked,
    Close,
}

/// Write the request, read the head, then read the body to its framing.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    request: &[u8],
) -> io::Result<Vec<u8>> {
    stream.write_all(request).await?;
    let mut raw = Vec::new();
    let mut buf = [0u8; 4096];
    // Scan for the end of the head from where the last scan stopped, less the
    // three bytes a terminator could have started in.
    let mut scanned = 0;
    let head_end = loop {
        if let Some(i) = find(&raw[scanned..], b"\r\n\r\n") {
            break scanned + i;
        }
        if raw.len() > MAX_HEAD {
            return Err(bad("response headers too large"));
        }
        scanned = raw.len().saturating_sub(3);
        let n = read_some(&mut stream, &mut buf).await?;
        if n == 0 {
            return Err(bad("incomplete HTTP response"));
        }
        raw.extend_from_slice(&buf[..n]);
    };
    let framing = parse_head(&raw[..head_end])?;
    let mut body = raw.split_off(head_end + 4);
    match framing {
        Framing::Length(n) => {
            if n > MAX_BODY {
                return Err(bad("response body too large"));
            }
            while body.len() < n {
                let got = read_some(&mut stream, &mut buf).await?;
                if got == 0 {
                    return Err(bad("truncated body"));
                }
                body.extend_from_slice(&buf[..got]);
            }
            body.truncate(n);
            Ok(body)
        }
        Framing::Chunked => {
            let mut decoder = Dechunker::default();
            loop {
                if decoder.feed(&body)? {
                    return Ok(decoder.out);
                }
                if body.len() > MAX_BODY + MAX_HEAD {
                    return Err(bad("response body too large"));
                }
                let got = read_some(&mut stream, &mut buf).await?;
                if got == 0 {
                    return Err(bad("truncated chunk"));
                }
                body.extend_from_slice(&buf[..got]);
            }
        }
        Framing::Close => loop {
            if body.len() > MAX_BODY {
                return Err(bad("response body too large"));
            }
            let got = read_some(&mut stream, &mut buf).await?;
            if got == 0 {
                return Ok(body);
            }
            body.extend_from_slice(&buf[..got]);
        },
    }
}

/// One read, treating a TLS peer's close without `close_notify` as an
/// ordinary end of stream: after a sized body it is harmless, and for a
/// close-terminated body it is the only end there is.
async fn read_some<S: AsyncRead + Unpin>(stream: &mut S, buf: &mut [u8]) -> io::Result<usize> {
    match stream.read(buf).await {
        Ok(n) => Ok(n),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
        Err(e) => Err(e),
    }
}

/// Check the status line and read the framing from the headers.
fn parse_head(head: &[u8]) -> io::Result<Framing> {
    let head = std::str::from_utf8(head).map_err(|_| bad("non-UTF-8 headers"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| bad("malformed status line"))?;
    if status != 200 {
        return Err(io::Error::other(format!(
            "unexpected response: {status_line}"
        )));
    }
    let mut framing = Framing::Close;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
            framing = Framing::Chunked;
        } else if name == "content-length" && !matches!(framing, Framing::Chunked) {
            let n = value.parse().map_err(|_| bad("malformed Content-Length"))?;
            framing = Framing::Length(n);
        }
    }
    Ok(framing)
}

/// An incremental chunked-body decoder: feed it the raw body as it grows and
/// it decodes from where it stopped last time. Trailers after the last chunk
/// are ignored. Every size is checked against the cap before any arithmetic
/// on it.
#[derive(Default)]
struct Dechunker {
    /// The decoded body so far.
    out: Vec<u8>,
    /// How much of the raw body has been consumed.
    consumed: usize,
    /// The terminating chunk has been seen; whatever follows is trailers.
    done: bool,
}

impl Dechunker {
    /// Decode what `raw` has beyond what was consumed. `Ok(true)` once the
    /// terminating chunk has arrived; `Ok(false)` means more bytes are needed.
    fn feed(&mut self, raw: &[u8]) -> io::Result<bool> {
        if self.done {
            return Ok(true);
        }
        loop {
            let body = &raw[self.consumed..];
            let Some(line_end) = find(body, b"\r\n") else {
                return Ok(false);
            };
            let size_str =
                std::str::from_utf8(&body[..line_end]).map_err(|_| bad("bad chunk size"))?;
            let size_str = size_str.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(size_str, 16).map_err(|_| bad("bad chunk size"))?;
            if size > MAX_BODY || self.out.len() + size > MAX_BODY {
                return Err(bad("response body too large"));
            }
            let data = &body[line_end + 2..];
            if size == 0 {
                self.consumed += line_end + 2;
                self.done = true;
                return Ok(true);
            }
            if data.len() < size + 2 {
                return Ok(false);
            }
            self.out.extend_from_slice(&data[..size]);
            self.consumed += line_end + 2 + size + 2;
        }
    }
}

/// Decode a complete chunked body in one go (tests).
#[cfg(test)]
fn dechunk(body: &[u8]) -> io::Result<Option<Vec<u8>>> {
    let mut d = Dechunker::default();
    Ok(d.feed(body)?.then_some(d.out))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    /// A one-shot server: accept one connection, read the request, write
    /// `response` verbatim, then close (or, with `linger`, hold the socket
    /// open for a while first).
    async fn serve_once(response: &'static str, linger: Option<Duration>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            socket.write_all(response.as_bytes()).await.unwrap();
            if let Some(d) = linger {
                tokio::time::sleep(d).await;
            }
            socket.shutdown().await.unwrap();
        });
        format!("http://{addr}/.well-known/tacenta")
    }

    #[tokio::test]
    async fn a_sized_body_is_returned() {
        let url = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{\"version\":1}",
            None,
        )
        .await;
        // Content-Length shorter than the bytes sent: only the declared length
        // is the body.
        let body = get(&url, &ClientTls::web_pki()).await.unwrap();
        assert_eq!(body, b"{\"version\":");
    }

    #[tokio::test]
    async fn a_sized_body_does_not_wait_for_the_close() {
        let url = serve_once(
            "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\n{\"version\":1}",
            Some(Duration::from_secs(30)),
        )
        .await;
        let body = get_within(&url, &ClientTls::web_pki(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(body, b"{\"version\":1}");
    }

    #[tokio::test]
    async fn a_chunked_body_is_decoded() {
        let url = serve_once(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"ve\r\n8\r\nrsion\":1\r\n1\r\n}\r\n0\r\n\r\n",
            Some(Duration::from_secs(30)),
        )
        .await;
        let body = get_within(&url, &ClientTls::web_pki(), Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(body, b"{\"version\":1}");
    }

    #[tokio::test]
    async fn a_body_terminated_by_close_is_returned() {
        let url = serve_once("HTTP/1.1 200 OK\r\n\r\n{\"version\":1}", None).await;
        let body = get(&url, &ClientTls::web_pki()).await.unwrap();
        assert_eq!(body, b"{\"version\":1}");
    }

    #[tokio::test]
    async fn a_non_200_is_an_error_carrying_the_status_line() {
        let url = serve_once("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", None).await;
        let err = get(&url, &ClientTls::web_pki()).await.unwrap_err();
        assert!(err.to_string().contains("404 Not Found"), "{err}");
    }

    #[tokio::test]
    async fn a_silent_server_is_a_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let err = get_within(
            &format!("http://{addr}/"),
            &ClientTls::web_pki(),
            Duration::from_millis(200),
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "{err}");
    }

    #[test]
    fn urls_parse_to_host_port_and_path() {
        let t = parse("https://tacenta.com/.well-known/tacenta").unwrap();
        assert!(t.tls);
        assert_eq!(
            (t.host.as_str(), t.port, t.path.as_str()),
            ("tacenta.com", 443, "/.well-known/tacenta")
        );
        assert_eq!(t.authority, "tacenta.com");
        let t = parse("http://127.0.0.1:4780").unwrap();
        assert!(!t.tls);
        assert_eq!(
            (t.host.as_str(), t.port, t.path.as_str()),
            ("127.0.0.1", 4780, "/")
        );
        assert_eq!(t.authority, "127.0.0.1:4780");
        assert!(parse("ftp://x/").is_err());
        assert!(parse("http:///x").is_err());
    }

    #[test]
    fn ipv6_literals_parse_with_and_without_a_port() {
        let t = parse("http://[::1]/x").unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.authority.as_str()),
            ("::1", 80, "[::1]")
        );
        let t = parse("https://[2001:db8::1]:4780/.well-known/tacenta").unwrap();
        assert_eq!(
            (t.host.as_str(), t.port, t.authority.as_str()),
            ("2001:db8::1", 4780, "[2001:db8::1]:4780")
        );
        assert!(parse("http://[::1/").is_err());
        assert!(parse("http://[::1]x/").is_err());
    }

    #[tokio::test]
    async fn an_oversized_body_is_refused_under_every_framing() {
        // Sized: refused from the header, before reading the body.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = socket.read(&mut [0u8; 1024]).await;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
                MAX_BODY + 1
            );
            socket.write_all(head.as_bytes()).await.unwrap();
            socket.write_all(&vec![b'x'; MAX_BODY + 1]).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let err = get(&format!("http://{addr}/"), &ClientTls::web_pki())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("too large"), "{err}");

        // Chunked: refused from the chunk size.
        assert!(dechunk(b"10001\r\n").is_err());

        // Close-terminated: refused as the bytes arrive; one byte fewer is fine.
        for (extra, ok) in [(0usize, true), (1, false)] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let _ = socket.read(&mut [0u8; 1024]).await;
                socket.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
                socket
                    .write_all(&vec![b'x'; MAX_BODY + extra])
                    .await
                    .unwrap();
                socket.shutdown().await.unwrap();
            });
            let res = get(&format!("http://{addr}/"), &ClientTls::web_pki()).await;
            assert_eq!(res.is_ok(), ok, "extra={extra}: {res:?}");
        }
    }

    #[test]
    fn chunks_split_across_reads_are_decoded_incrementally() {
        let raw = b"4\r\n{\"ve\r\n8\r\nrsion\":1\r\n1\r\n}\r\n0\r\n\r\n";
        let mut d = Dechunker::default();
        for cut in 1..raw.len() {
            let done = d.feed(&raw[..cut]).unwrap();
            assert!(!done || cut >= raw.len() - 2, "finished early at {cut}");
        }
        assert!(d.feed(raw).unwrap());
        assert_eq!(d.out, b"{\"version\":1}");
    }

    #[test]
    fn a_chunk_size_near_usize_max_is_an_error_not_a_panic() {
        for line in [
            "ffffffffffffffff\r\nx",
            "fffffffffffffffe\r\nx",
            "10001\r\n",
        ] {
            let err = dechunk(line.as_bytes()).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{line:?}");
        }
        // An incomplete chunk asks for more rather than failing.
        assert!(dechunk(b"4\r\n{\"v").unwrap().is_none());
        assert!(dechunk(b"4\r\n").unwrap().is_none());
    }
}
