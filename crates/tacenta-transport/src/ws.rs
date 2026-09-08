//! The WebSocket carriage of the framed services (decision 0090).
//!
//! A browser cannot open a TCP socket, so the gateway offers each of the
//! four services at `{ws}/{service}` as a WebSocket, and pipes bytes to the
//! service's TCP port. This module is the client side of that in Rust: a
//! [`WsStream`] presents a WebSocket as an `AsyncRead + AsyncWrite` byte
//! stream, so the existing `establish` paths speak the unchanged framing over
//! it, and [`connect`] opens one over this crate's own TCP and TLS. Every
//! write becomes one binary message; reads concatenate binary messages, so
//! message boundaries carry no meaning and the framing is the only framing.
//!
//! Text messages are a protocol error, and a close frame is end of stream.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use crate::url::Target;
use crate::{AccountConnection, ClientTls, Connection, DirConnection, ProvisionConnection};

/// The stream under a client WebSocket: TCP, or TLS over TCP.
pub enum MaybeTls {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for MaybeTls {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTls::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTls {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTls::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => Pin::new(s).poll_flush(cx),
            MaybeTls::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            MaybeTls::Plain(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTls::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// A WebSocket presented as a byte stream; see the module documentation.
pub struct WsStream<S> {
    inner: WebSocketStream<S>,
    /// Bytes of the last binary message not yet handed to a reader.
    pending: Bytes,
    /// A close frame or the end of the stream has been seen.
    eof: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsStream<S> {
    /// Wrap an accepted or connected WebSocket.
    pub fn new(inner: WebSocketStream<S>) -> WsStream<S> {
        WsStream {
            inner,
            pending: Bytes::new(),
            eof: false,
        }
    }
}

fn io_err(e: tokio_tungstenite::tungstenite::Error) -> io::Error {
    use tokio_tungstenite::tungstenite::Error as E;
    match e {
        E::Io(e) => e,
        E::ConnectionClosed | E::AlreadyClosed => {
            io::Error::new(io::ErrorKind::UnexpectedEof, "websocket closed")
        }
        other => io::Error::other(other),
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.pending.is_empty() {
                let n = self.pending.len().min(buf.remaining());
                buf.put_slice(&self.pending[..n]);
                let _ = self.pending.split_to(n);
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                Some(Ok(Message::Binary(b))) => self.pending = b,
                Some(Ok(Message::Text(_))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "text message on a binary carriage",
                    )));
                }
                // Pings are answered by the library on the next poll; pongs
                // and raw frames carry nothing for us.
                Some(Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_))) => {}
                Some(Ok(Message::Close(_))) | None => self.eof = true,
                Some(Err(e)) => return Poll::Ready(Err(io_err(e))),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(Pin::new(&mut self.inner).poll_ready(cx)).map_err(io_err)?;
        Pin::new(&mut self.inner)
            .start_send(Message::Binary(Bytes::copy_from_slice(buf)))
            .map_err(io_err)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx).map_err(io_err)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx).map_err(io_err)
    }
}

/// Open a WebSocket at `url` (`ws://` or `wss://`), over this crate's own TCP
/// and, for `wss://`, TLS under `tls` presenting the URL's host. The
/// handshake is the WebSocket library's; the bytes under it are ours.
pub async fn connect(url: &str, tls: &ClientTls) -> io::Result<WsStream<MaybeTls>> {
    let target = Target::parse(url)?;
    if !matches!(target.scheme.as_str(), "ws" | "wss") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "url must start with ws:// or wss://",
        ));
    }
    let tcp = TcpStream::connect((target.host.as_str(), target.port)).await?;
    let io = if target.tls {
        MaybeTls::Tls(Box::new(tls.wrap_tcp(&target.host, tcp).await?))
    } else {
        MaybeTls::Plain(tcp)
    };
    let (stream, _response) = tokio_tungstenite::client_async(url, io)
        .await
        .map_err(io_err)?;
    Ok(WsStream::new(stream))
}

impl AccountConnection {
    /// [`connect`](AccountConnection::connect) over the WebSocket at `url`.
    pub async fn connect_ws(url: &str, tls: &ClientTls) -> io::Result<AccountConnection> {
        AccountConnection::establish(connect(url, tls).await?).await
    }
}

impl DirConnection {
    /// [`connect`](DirConnection::connect) over the WebSocket at `url`.
    pub async fn connect_ws(url: &str, tls: &ClientTls) -> io::Result<DirConnection> {
        DirConnection::establish(connect(url, tls).await?).await
    }
}

impl ProvisionConnection {
    /// [`connect`](ProvisionConnection::connect) over the WebSocket at `url`.
    pub async fn connect_ws(url: &str, tls: &ClientTls) -> io::Result<ProvisionConnection> {
        ProvisionConnection::establish(connect(url, tls).await?).await
    }
}

impl Connection {
    /// [`connect_as`](Connection::connect_as) over the WebSocket at `url`.
    pub async fn connect_as_ws(
        url: &str,
        tls: &ClientTls,
        device: &tacenta_relay::DeviceAddr,
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> io::Result<Connection> {
        Connection::establish(connect(url, tls).await?, device, sign).await
    }

    /// [`connect_as_ws`](Connection::connect_as_ws), pinging `signal` as
    /// [`establish_with_signal`](Connection::establish_with_signal) does.
    pub async fn connect_as_ws_with_signal(
        url: &str,
        tls: &ClientTls,
        device: &tacenta_relay::DeviceAddr,
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
        signal: std::sync::Arc<tokio::sync::Notify>,
    ) -> io::Result<Connection> {
        Connection::establish_with_signal(connect(url, tls).await?, device, sign, signal).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{read_frame, write_frame};
    use tokio::net::TcpListener;

    /// A WebSocket server that echoes the framed protocol: reads frames off
    /// a `WsStream` and writes each one back, so the test proves the byte
    /// stream carries the framing in both directions across messages.
    async fn framed_echo_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            let mut stream = WsStream::new(ws);
            while let Ok(Some(frame)) = read_frame(&mut stream).await {
                write_frame(&mut stream, &frame).await.unwrap();
            }
        });
        format!("ws://{addr}/v1/ws/echo")
    }

    #[tokio::test]
    async fn frames_round_trip_over_a_websocket() {
        let url = framed_echo_server().await;
        let mut ws = connect(&url, &ClientTls::web_pki()).await.unwrap();
        for payload in [&b"hello"[..], &[0u8; 70_000][..], b""] {
            write_frame(&mut ws, payload).await.unwrap();
            let back = read_frame(&mut ws).await.unwrap().unwrap();
            assert_eq!(back, payload);
        }
        // The framing survives a read that spans messages: two frames sent
        // back to back arrive as two frames.
        write_frame(&mut ws, b"one").await.unwrap();
        write_frame(&mut ws, b"two").await.unwrap();
        assert_eq!(read_frame(&mut ws).await.unwrap().unwrap(), b"one");
        assert_eq!(read_frame(&mut ws).await.unwrap().unwrap(), b"two");
    }

    #[tokio::test]
    async fn a_text_message_is_a_protocol_error_and_close_is_eof() {
        use futures_util::SinkExt;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            ws.send(Message::Text("nope".into())).await.unwrap();
            ws.close(None).await.unwrap();
        });
        let mut ws = connect(&format!("ws://{addr}/"), &ClientTls::web_pki())
            .await
            .unwrap();
        let err = read_frame(&mut ws).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
        assert!(read_frame(&mut ws).await.unwrap().is_none());
    }

    #[test]
    fn only_websocket_urls_are_accepted() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(connect("http://127.0.0.1:1/", &ClientTls::web_pki()))
            .map(|_| ())
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
