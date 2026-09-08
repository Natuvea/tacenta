//! A TCP transport for the relay, with server push.
//!
//! The server authenticates each connection (decision record 0015) and
//! then serves the request/response protocol (decision record 0013). It
//! also *pushes*: when a message is routed to a device that has a
//! connected client, that client is notified so it can fetch without
//! polling. The relay stays blind and synchronous — the transport
//! decodes only enough of a request to know a `Send`'s recipient, so it
//! can wake that device's connection (decision record 0017).
//!
//! Framing on the stream is `[u32 big-endian length][frame bytes]`.
//! After the handshake, every server→client frame carries a one-byte
//! tag: `0` = a response to a request, `1` = a push notification. The
//! serve/connect paths are generic over the byte stream, so the same
//! frames run over plain TCP or over TLS (`serve_tls` / `connect_as_tls`,
//! decision record 0023), and, behind the `ws` feature, over a WebSocket
//! carrying the same framing as binary messages (decision 0090).

// On wasm the server side of every service is compiled but never called
// (a browser only connects), which is dead code by that target's lights
// and live code by the crate's.
#![cfg_attr(target_arch = "wasm32", allow(dead_code))]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;
use tacenta_relay::{DeviceAddr, Relay, Request, Response, decode_request, encode_response};
// Used only by the connection-serving code, which is native-only.
#[cfg(not(target_arch = "wasm32"))]
use tacenta_relay::decode_auth;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(not(target_arch = "wasm32"))]
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::{Notify, mpsc};

mod accounts;
mod directory;
#[cfg(not(target_arch = "wasm32"))]
mod http;
mod provisioning;
#[cfg(not(target_arch = "wasm32"))]
mod tls;
#[cfg(target_arch = "wasm32")]
#[path = "tls_stub.rs"]
mod tls;

/// Run `future` in the background: on a native target a tokio task, in the
/// browser a task on the event loop. The reader behind every connection
/// type runs through here, which is what lets the same connection code
/// serve both.
pub(crate) fn spawn<F>(future: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    #[cfg(not(target_arch = "wasm32"))]
    {
        tokio::spawn(future);
    }
    #[cfg(target_arch = "wasm32")]
    {
        wasm_bindgen_futures::spawn_local(future);
    }
}
pub use accounts::{AccountConnection, AccountServer, account_server};
#[cfg(not(target_arch = "wasm32"))]
pub use accounts::{
    serve_accounts, serve_accounts_tls, serve_accounts_tls_with_limits, serve_accounts_with_limits,
};
pub use directory::{
    DirConnection, DirServer, Possession, RegistrationPolicy, dir_server, dir_server_gated,
    dir_server_with_limit,
};
#[cfg(not(target_arch = "wasm32"))]
pub use directory::{
    serve_directory, serve_directory_tls, serve_directory_tls_with_limits,
    serve_directory_with_limits,
};
#[cfg(not(target_arch = "wasm32"))]
pub use http::{DEFAULT_TIMEOUT as HTTP_TIMEOUT, get as http_get, get_within as http_get_within};
#[cfg(not(target_arch = "wasm32"))]
mod url;
#[cfg(all(feature = "ws", not(target_arch = "wasm32")))]
pub mod ws;
pub use provisioning::{
    ProvisionConnection, ProvisionOutcome, ProvisionRequest, Provisioner, decode_provision_outcome,
    decode_provision_request, encode_provision_outcome, encode_provision_request,
};
#[cfg(not(target_arch = "wasm32"))]
pub use provisioning::{
    serve_provisioning, serve_provisioning_tls, serve_provisioning_tls_with_limits,
    serve_provisioning_with_limits,
};
pub use tls::ClientTls;
#[cfg(not(target_arch = "wasm32"))]
pub use tls::ServerTls;
pub use tls::trust_for;

const TAG_RESPONSE: u8 = 0;
const TAG_PUSH: u8 = 1;

/// Verifies a client's identity during the connection handshake. The
/// transport owns the handshake *protocol* but delegates the *crypto* —
/// producing an unpredictable challenge and checking the signature over
/// it — to an implementation of this trait, so the transport itself
/// stays free of any cryptographic dependency.
pub trait Authenticator: Send + Sync + 'static {
    /// A fresh, unpredictable challenge for one connection.
    fn challenge(&self) -> Vec<u8>;

    /// Whether `signature` is a valid signature over `challenge` by the
    /// identity registered for `device`. `false` rejects the connection.
    fn verify(&self, device: &DeviceAddr, challenge: &[u8], signature: &[u8]) -> bool;

    /// Whether `device` is a recipient this deployment knows about, so a
    /// `Send` can be refused before it creates a queue.
    ///
    /// **Defaults to `true`, which is the permissive answer, and that is
    /// deliberate.** An implementor with no registration view should not have
    /// its behaviour changed by this method appearing; the deployment that has
    /// a directory is the one that overrides it. The alternative default would
    /// silently break every embedder on upgrade.
    ///
    /// This lives on `Authenticator` because that trait already resolves an
    /// address to a registration — `verify` reads the bound identity — so the
    /// view is here and nothing new has to be threaded through the transport.
    fn knows_recipient(&self, _device: &DeviceAddr) -> bool {
        true
    }
}

/// A relay, its authenticator, and the set of currently connected
/// devices (each with a channel to push notifications to). The relay is
/// locked only for the synchronous request dispatch — never across an
/// `await`.
pub struct Server<A: Authenticator> {
    relay: Mutex<Relay>,
    auth: A,
    connected: Mutex<HashMap<DeviceAddr, mpsc::UnboundedSender<()>>>,
}

/// Wrap a relay and an authenticator for sharing across connections.
pub fn server<A: Authenticator>(relay: Relay, auth: A) -> Arc<Server<A>> {
    Arc::new(Server {
        relay: Mutex::new(relay),
        auth,
        connected: Mutex::new(HashMap::new()),
    })
}

impl<A: Authenticator> Server<A> {
    /// Snapshot the running server's relay state to bytes a caller can
    /// persist (write to disk on a schedule or at shutdown) and later
    /// hand to `Relay::restore` + `server(...)` to come back up with the
    /// queues intact. Takes the relay lock briefly and nothing else.
    pub fn snapshot(&self) -> Vec<u8> {
        self.relay.lock().expect("relay mutex poisoned").snapshot()
    }
}

/// The largest frame `read_frame` will allocate for.
///
/// **This bounds an allocate-from-the-wire DoS.** The
/// length prefix is attacker-controlled on a public listener, and without a
/// ceiling `read_frame` would `vec![0u8; len]` for any `u32` — up to ~4 GiB per
/// frame — before reading a byte of body or authenticating anything. The
/// relay's `MAX_PENDING` bounds message *count*, not size, so the count cap
/// alone leaves this open.
///
/// 16 MiB is a deliberately generous ceiling: every legitimate frame here is a
/// protocol message — a challenge, an auth frame, a register bundle, a message
/// envelope — and all sit far below it, while a hostile frame is now bounded to
/// megabytes rather than gigabytes. This is the baseline budget; the relay
/// refines it per envelope and per queue. If a legitimate frame ever needs to
/// exceed this, the limit moves with a reason, it is not removed.
pub(crate) const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// The limits every accepted server connection is served under. Without
/// them a client could open thousands of connections, or one and never
/// speak, and hold the resources open.
///
/// - `max_connections` caps how many run at once; past it a new connection
///   is closed at once rather than queued, so the cost of a flood is bounded.
/// - `handshake` bounds how long a client may take to send its first frame
///   after the server's challenge — the slow-loris a request/response
///   service is otherwise open to.
/// - `idle` bounds the gap between requests on the request/response services
///   (directory, accounts, provisioning); the relay is exempt, since it
///   waits for pushes with nothing to read, and leans on keepalive instead.
/// - `keepalive` is the OS TCP keepalive set on every accepted socket, so a
///   peer that vanished is reaped even on a silent long-lived connection.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Copy)]
pub struct ServeLimits {
    pub max_connections: usize,
    pub handshake: Duration,
    pub idle: Duration,
    pub keepalive: Duration,
}

#[cfg(not(target_arch = "wasm32"))]
impl Default for ServeLimits {
    fn default() -> Self {
        // Generous enough that no legitimate client meets them, tight enough
        // that a flood or a stalled peer is bounded. The operator raises
        // `max_connections` for a large node (`TACENTA_MAX_CONNECTIONS`).
        ServeLimits {
            max_connections: 8192,
            handshake: Duration::from_secs(10),
            idle: Duration::from_secs(300),
            keepalive: Duration::from_secs(60),
        }
    }
}

/// Set OS TCP keepalive on an accepted socket; best effort, since a socket
/// that refuses the option still serves.
#[cfg(not(target_arch = "wasm32"))]
fn set_keepalive(stream: &TcpStream, after: Duration) {
    let params = socket2::TcpKeepalive::new().with_time(after);
    let _ = socket2::SockRef::from(stream).set_tcp_keepalive(&params);
}

/// Read one frame, or `Ok(None)` if none arrives within `within` — an idle
/// or slow client is closed as if it had hung up, which is what the caller
/// does with `Ok(None)`.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn read_frame_within<R: AsyncRead + Unpin>(
    stream: &mut R,
    within: Duration,
) -> std::io::Result<Option<Vec<u8>>> {
    match tokio::time::timeout(within, read_frame(stream)).await {
        Ok(result) => result,
        Err(_elapsed) => Ok(None),
    }
}

/// Accept connections forever, each served by `handle`, under `limits`:
/// keepalive on the socket, and a semaphore that closes a connection at
/// once when the cap is reached rather than queueing it. The permit is held
/// for the connection's life. Returns only on a fatal accept error.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) async fn accept_loop<F, Fut>(
    listener: TcpListener,
    limits: ServeLimits,
    handle: F,
) -> std::io::Result<()>
where
    F: Fn(TcpStream, std::net::SocketAddr) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let capacity = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
    loop {
        let (stream, peer) = listener.accept().await?;
        let Ok(permit) = capacity.clone().try_acquire_owned() else {
            // At capacity: close now rather than pile up unbounded work.
            drop(stream);
            continue;
        };
        set_keepalive(&stream, limits.keepalive);
        let fut = handle(stream, peer);
        tokio::spawn(async move {
            let _permit = permit;
            fut.await;
        });
    }
}

/// Read one length-prefixed frame. `Ok(None)` at a clean end of stream.
pub(crate) async fn read_frame<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_bytes = [0u8; 4];
    match stream.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_bytes) as usize;
    // Reject before allocating: the length is attacker-controlled.
    if len > MAX_FRAME_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "frame length exceeds the maximum",
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

/// Write one length-prefixed frame.
pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(
    stream: &mut W,
    data: &[u8],
) -> std::io::Result<()> {
    let len = u32::try_from(data.len()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "frame exceeds u32 length")
    })?;
    // One write: the prefix and the body together, so a message-framed
    // carriage (the WebSocket) sends one message per frame and a socket
    // sends one segment.
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
    stream.write_all(&buf).await?;
    stream.flush().await
}

/// Write a tagged server→client frame (`[tag][payload]`).
async fn write_tagged<W: AsyncWrite + Unpin>(
    stream: &mut W,
    tag: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let mut framed = Vec::with_capacity(1 + payload.len());
    framed.push(tag);
    framed.extend_from_slice(payload);
    write_frame(stream, &framed).await
}

/// Authenticate a connection, then serve its requests as the
/// authenticated device while pushing notifications of new mail. Generic
/// over the byte stream, so it serves plain TCP or a TLS stream over TCP
/// identically — the framed protocol is the same on either.
#[cfg(not(target_arch = "wasm32"))]
async fn serve_connection<S, A>(
    mut stream: S,
    server: Arc<Server<A>>,
    limits: ServeLimits,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    A: Authenticator,
{
    // Handshake (untagged frames): challenge, signed response, accept byte.
    // The auth frame is bounded: a peer that connects and never
    // authenticates is closed rather than left holding a slot. The
    // post-handshake loop is not bounded this way — it waits for pushes with
    // nothing to read — so keepalive reaps a dead peer there instead.
    let challenge = server.auth.challenge();
    write_frame(&mut stream, &challenge).await?;
    let Some(auth_frame) = read_frame_within(&mut stream, limits.handshake).await? else {
        return Ok(());
    };
    let Some((device, signature)) = decode_auth(&auth_frame) else {
        write_frame(&mut stream, &[0]).await?;
        return Ok(());
    };
    if !server.auth.verify(&device, &challenge, &signature) {
        write_frame(&mut stream, &[0]).await?;
        return Ok(());
    }
    write_frame(&mut stream, &[1]).await?;

    // Register this device's push channel for the duration of the
    // connection, cleaning up on exit.
    let (push_tx, mut push_rx) = mpsc::unbounded_channel::<()>();
    server
        .connected
        .lock()
        .expect("connected mutex poisoned")
        .insert(device.clone(), push_tx.clone());
    let result = serve_authenticated(&mut stream, &server, &device, &mut push_rx).await;
    // Remove only this connection's registration: a device that signed in
    // again while this connection was still draining has replaced it, and
    // that live registration must not be evicted by the stale one's exit.
    let mut connected = server.connected.lock().expect("connected mutex poisoned");
    if connected
        .get(&device)
        .is_some_and(|live| live.same_channel(&push_tx))
    {
        connected.remove(&device);
    }
    drop(connected);
    result
}

/// The post-handshake loop: interleave request handling and push
/// delivery on one connection. A single task owns the socket, so
/// responses and pushes never race for the writer.
async fn serve_authenticated<S, A>(
    stream: &mut S,
    server: &Arc<Server<A>>,
    device: &DeviceAddr,
    push_rx: &mut mpsc::UnboundedReceiver<()>,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    A: Authenticator,
{
    loop {
        tokio::select! {
            frame = read_frame(stream) => {
                let Some(frame) = frame? else { return Ok(()) };
                let Some(request) = decode_request(&frame) else { return Ok(()) };
                // The recipient of a Send is who we may need to wake.
                let recipient = match &request {
                    Request::Send { to, .. } => Some(to.clone()),
                    _ => None,
                };
                // **Refuse a Send to an address nobody has registered,
                // before the relay sees it.** `Relay::enqueue` creates a queue
                // on demand for whatever address it is handed, so an attacker
                // could mint queues for addresses that will never exist and
                // never drain. Gating here rather than inside the relay keeps
                // the relay blind -- it still routes to any device it is asked
                // about -- and leaves the proven `Session` model untouched.
                //
                // No legitimate sender is affected: establishing a session
                // needs the recipient's published bundle, so a client cannot
                // even construct a message for an address the directory does
                // not know.
                let unknown = recipient
                    .as_ref()
                    .is_some_and(|to| !server.auth.knows_recipient(to));
                let response = if unknown {
                    encode_response(&Response::UnknownRecipient)
                } else {
                    let mut relay = server.relay.lock().expect("relay mutex poisoned");
                    encode_response(&relay.handle(device, request))
                };
                write_tagged(stream, TAG_RESPONSE, &response).await?;
                // Only wake a recipient we actually enqueued for.
                if let Some(recipient) = recipient.filter(|_| !unknown) {
                    notify(server, &recipient);
                }
            }
            push = push_rx.recv() => {
                // `None` cannot occur while this task holds the sender.
                if push.is_some() {
                    write_tagged(stream, TAG_PUSH, &[]).await?;
                }
            }
        }
    }
}

/// Wake a device's connection if it is connected. A closed receiver
/// (a race with disconnect) is harmless.
fn notify<A: Authenticator>(server: &Arc<Server<A>>, device: &DeviceAddr) {
    if let Some(tx) = server
        .connected
        .lock()
        .expect("connected mutex poisoned")
        .get(device)
    {
        let _ = tx.send(());
    }
}

/// Accept connections forever, serving each against the shared server.
/// Returns only on a fatal accept error.
#[cfg(not(target_arch = "wasm32"))]
pub async fn serve<A: Authenticator>(
    listener: TcpListener,
    server: Arc<Server<A>>,
) -> std::io::Result<()> {
    serve_with_limits(listener, server, ServeLimits::default()).await
}

/// [`serve`] under explicit [`ServeLimits`].
#[cfg(not(target_arch = "wasm32"))]
pub async fn serve_with_limits<A: Authenticator>(
    listener: TcpListener,
    server: Arc<Server<A>>,
    limits: ServeLimits,
) -> std::io::Result<()> {
    accept_loop(listener, limits, move |stream, _peer| {
        let server = server.clone();
        // A per-connection error just ends that connection.
        async move {
            let _ = serve_connection(stream, server, limits).await;
        }
    })
    .await
}

/// Like [`serve`], but each accepted connection is wrapped in TLS before the
/// framed protocol runs. A failed TLS handshake just ends that connection.
#[cfg(not(target_arch = "wasm32"))]
pub async fn serve_tls<A: Authenticator>(
    listener: TcpListener,
    server: Arc<Server<A>>,
    tls: ServerTls,
) -> std::io::Result<()> {
    serve_tls_with_limits(listener, server, tls, ServeLimits::default()).await
}

/// [`serve_tls`] under explicit [`ServeLimits`].
#[cfg(not(target_arch = "wasm32"))]
pub async fn serve_tls_with_limits<A: Authenticator>(
    listener: TcpListener,
    server: Arc<Server<A>>,
    tls: ServerTls,
    limits: ServeLimits,
) -> std::io::Result<()> {
    accept_loop(listener, limits, move |tcp, _peer| {
        let server = server.clone();
        let acceptor = tls.acceptor.clone();
        async move {
            if let Ok(stream) = acceptor.accept(tcp).await {
                let _ = serve_connection(stream, server, limits).await;
            }
        }
    })
    .await
}

/// A client connection to a relay server, authenticated as one device.
/// A background task reads the socket and demultiplexes server frames
/// into responses (paired with requests) and push notifications. The write
/// half is boxed so the connection is agnostic to the underlying stream
/// (plain TCP, TLS over TCP, or the WebSocket carriage).
pub struct Connection {
    write: Box<dyn AsyncWrite + Unpin + Send + Sync>,
    responses: mpsc::UnboundedReceiver<Vec<u8>>,
    pushes: mpsc::UnboundedReceiver<()>,
    /// Pinged on every push and when the reader ends, for a waiter that
    /// holds no reference to the connection (see [`Connection::establish_with_signal`]).
    signal: Arc<Notify>,
    /// Dropped with the connection, which ends the reader task and with it
    /// the socket; nothing lingers on the runtime once the caller lets go.
    _stop: tokio::sync::oneshot::Sender<()>,
}

impl Connection {
    /// Connect over TCP and authenticate as `device`. `sign` produces the
    /// device's signature over the server's challenge (the caller owns
    /// the identity key and the signing crypto). Fails if the server
    /// rejects the identity.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect_as(
        addr: impl ToSocketAddrs,
        device: &DeviceAddr,
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> std::io::Result<Connection> {
        Connection::connect_as_with_signal(addr, device, sign, Arc::new(Notify::new())).await
    }

    /// [`connect_as`](Connection::connect_as), pinging `signal` as
    /// [`establish_with_signal`](Connection::establish_with_signal) does.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect_as_with_signal(
        addr: impl ToSocketAddrs,
        device: &DeviceAddr,
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
        signal: Arc<Notify>,
    ) -> std::io::Result<Connection> {
        let stream = TcpStream::connect(addr).await?;
        Connection::establish_with_signal(stream, device, sign, signal).await
    }

    /// Connect over TLS to a server presenting `server_name`, then
    /// authenticate as `device`. `tls` decides which server certificate to
    /// trust. The handshake runs inside the encrypted stream.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect_as_tls(
        addr: impl ToSocketAddrs,
        server_name: &str,
        tls: &ClientTls,
        device: &DeviceAddr,
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> std::io::Result<Connection> {
        Connection::connect_as_tls_with_signal(
            addr,
            server_name,
            tls,
            device,
            sign,
            Arc::new(Notify::new()),
        )
        .await
    }

    /// [`connect_as_tls`](Connection::connect_as_tls), pinging `signal` as
    /// [`establish_with_signal`](Connection::establish_with_signal) does.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect_as_tls_with_signal(
        addr: impl ToSocketAddrs,
        server_name: &str,
        tls: &ClientTls,
        device: &DeviceAddr,
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
        signal: Arc<Notify>,
    ) -> std::io::Result<Connection> {
        let tcp = TcpStream::connect(addr).await?;
        let stream = tls.wrap(server_name, tcp).await?;
        Connection::establish_with_signal(stream, device, sign, signal).await
    }

    /// Authenticate as `device` over an already-connected `stream`, then
    /// start the reader task. The transport layer — TCP, or TLS over TCP —
    /// is the caller's; this speaks the framed protocol over whatever it is
    /// given, so a TLS client wraps a stream and calls this.
    pub async fn establish<S>(
        stream: S,
        device: &DeviceAddr,
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> std::io::Result<Connection>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    {
        Connection::establish_with_signal(stream, device, sign, Arc::new(Notify::new())).await
    }

    /// [`establish`](Connection::establish), pinging `signal` on every push
    /// the server sends and once when the reader ends. A client hands the
    /// same signal to every connection it makes, so something that wants to
    /// wait for mail can do so without holding the connection, or the
    /// client, and then poll: the wait is a `Notify` with a stored permit,
    /// so a push that lands between a poll and the wait is not missed.
    pub async fn establish_with_signal<S>(
        mut stream: S,
        device: &DeviceAddr,
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
        signal: Arc<Notify>,
    ) -> std::io::Result<Connection>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let challenge = read_frame(&mut stream).await?.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no challenge")
        })?;
        let signature = sign(&challenge);
        write_frame(&mut stream, &tacenta_relay::encode_auth(device, &signature)).await?;
        match read_frame(&mut stream).await?.as_deref() {
            Some([1]) => {}
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "authentication rejected",
                ));
            }
        }

        // Split the stream; a reader task routes tagged frames.
        let (mut read, write) = tokio::io::split(stream);
        let (resp_tx, responses) = mpsc::unbounded_channel();
        let (push_tx, pushes) = mpsc::unbounded_channel();
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
        let reader_signal = signal.clone();
        crate::spawn(async move {
            loop {
                let frame = tokio::select! {
                    _ = &mut stop_rx => break,
                    read = read_frame(&mut read) => match read {
                        Ok(Some(frame)) => frame,
                        _ => break,
                    },
                };
                match frame.split_first() {
                    Some((&TAG_RESPONSE, body)) => {
                        if resp_tx.send(body.to_vec()).is_err() {
                            break;
                        }
                    }
                    Some((&TAG_PUSH, _)) => {
                        reader_signal.notify_one();
                        if push_tx.send(()).is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }
            // The connection is gone: every waiter polls, meets the error,
            // and reconnects, rather than waiting on a socket that will never
            // push again; the permit is for a waiter that arrives later.
            reader_signal.notify_waiters();
            reader_signal.notify_one();
        });

        Ok(Connection {
            write: Box::new(write),
            responses,
            _stop: stop_tx,
            pushes,
            signal,
        })
    }

    /// Send an encoded request frame and await the encoded response.
    /// The caller encodes/decodes with `tacenta_relay`'s protocol
    /// functions; this only moves bytes.
    pub async fn request(&mut self, request: &[u8]) -> std::io::Result<Vec<u8>> {
        write_frame(&mut self.write, request).await?;
        self.responses
            .recv()
            .await
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no response"))
    }

    /// Await the next push notification: the server signals that mail has
    /// arrived for this device (the client then polls to fetch it).
    /// `None` if the connection has closed.
    pub async fn next_notification(&mut self) -> Option<()> {
        self.pushes.recv().await
    }

    /// The signal this connection pings on every push and when it ends.
    pub fn signal(&self) -> Arc<Notify> {
        self.signal.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tacenta_relay::{Request, StoredMessage, decode_response, encode_request};
    use tacenta_wire::{Envelope, Kind};

    fn env(byte: u8) -> Envelope {
        Envelope {
            kind: Kind::Dm,
            payload: vec![byte, byte],
        }
    }

    fn msg(from: &DeviceAddr, byte: u8) -> StoredMessage {
        StoredMessage {
            from: from.clone(),
            envelope: env(byte),
        }
    }

    /// A trivial authenticator for transport tests: the "signature" is
    /// the device name, so no real crypto is exercised here — the crypto
    /// path is validated in `tacenta-core`'s networked test. This still
    /// runs the full handshake shape (challenge, response, accept/reject).
    struct NameAuth;
    impl Authenticator for NameAuth {
        fn challenge(&self) -> Vec<u8> {
            b"fixed-test-challenge".to_vec()
        }
        fn verify(&self, device: &DeviceAddr, _challenge: &[u8], signature: &[u8]) -> bool {
            signature == device.user.as_bytes()
        }
    }

    fn sign_as(device: &DeviceAddr) -> impl FnOnce(&[u8]) -> Vec<u8> {
        let user = device.user.clone();
        move |_challenge| user.into_bytes()
    }

    /// A frame whose length prefix exceeds the cap is refused **before** the
    /// buffer is allocated: the reader sees only the 4 length bytes, not
    /// a body of the claimed size, so a hostile `u32` cannot make it allocate
    /// gigabytes. The under-cap case still reads its body normally.
    #[tokio::test]
    async fn an_oversized_frame_length_is_refused_before_allocating() {
        // Just the length prefix, claiming one byte past the cap; no body.
        let huge = ((MAX_FRAME_LEN + 1) as u32).to_be_bytes();
        let err = read_frame(&mut &huge[..]).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        // The all-ones u32 (~4 GiB) is refused the same way, on 4 bytes of input.
        let max_u32 = u32::MAX.to_be_bytes();
        assert_eq!(
            read_frame(&mut &max_u32[..]).await.unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );

        // A legitimate small frame still round-trips: length prefix + body.
        let mut ok = 3u32.to_be_bytes().to_vec();
        ok.extend_from_slice(b"hey");
        assert_eq!(read_frame(&mut &ok[..]).await.unwrap().unwrap(), b"hey");
    }

    /// A client authenticates over a real TCP socket, then exchanges
    /// frames: send two envelopes, poll them back, acknowledge, poll
    /// empty, and a cross-device poll is refused.
    #[tokio::test]
    async fn client_and_server_over_tcp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, server(Relay::new(), NameAuth)));

        let bob = DeviceAddr::new("+bob", 1);
        let mut conn = Connection::connect_as(addr, &bob, sign_as(&bob))
            .await
            .unwrap();

        for e in [env(0x10), env(0x20)] {
            let resp = conn
                .request(&encode_request(&Request::Send {
                    to: bob.clone(),
                    envelope: e,
                }))
                .await
                .unwrap();
            assert_eq!(decode_response(&resp), Some(Response::Ok));
        }

        let resp = conn
            .request(&encode_request(&Request::Poll {
                device: bob.clone(),
            }))
            .await
            .unwrap();
        assert_eq!(
            decode_response(&resp),
            Some(Response::Delivered {
                from: 0,
                messages: vec![msg(&bob, 0x10), msg(&bob, 0x20)],
            })
        );

        let resp = conn
            .request(&encode_request(&Request::Ack {
                device: bob.clone(),
                up_to: 2,
            }))
            .await
            .unwrap();
        assert_eq!(
            decode_response(&resp),
            Some(Response::Acked { accepted: true })
        );

        let resp = conn
            .request(&encode_request(&Request::Poll {
                device: bob.clone(),
            }))
            .await
            .unwrap();
        assert_eq!(
            decode_response(&resp),
            Some(Response::Delivered {
                from: 2,
                messages: vec![]
            })
        );

        // Polling a *different* device's queue is refused by the relay.
        let resp = conn
            .request(&encode_request(&Request::Poll {
                device: DeviceAddr::new("+someone-else", 1),
            }))
            .await
            .unwrap();
        assert_eq!(decode_response(&resp), Some(Response::Unauthorized));
    }

    /// A client that cannot produce a valid signature is rejected at the
    /// handshake — it never reaches the request loop.
    #[tokio::test]
    async fn bad_signature_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, server(Relay::new(), NameAuth)));

        let bob = DeviceAddr::new("+bob", 1);
        let result = Connection::connect_as(addr, &bob, |_challenge| b"wrong".to_vec()).await;
        assert!(result.is_err());
    }

    /// When Alice sends to Bob, Bob's connected client is pushed a
    /// notification — no polling required to learn mail arrived.
    #[tokio::test]
    async fn recipient_is_pushed_on_send() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, server(Relay::new(), NameAuth)));

        let alice = DeviceAddr::new("+alice", 1);
        let bob = DeviceAddr::new("+bob", 1);
        let mut alice_conn = Connection::connect_as(addr, &alice, sign_as(&alice))
            .await
            .unwrap();
        let mut bob_conn = Connection::connect_as(addr, &bob, sign_as(&bob))
            .await
            .unwrap();

        // Alice sends to Bob.
        let resp = alice_conn
            .request(&encode_request(&Request::Send {
                to: bob.clone(),
                envelope: env(0x42),
            }))
            .await
            .unwrap();
        assert_eq!(decode_response(&resp), Some(Response::Ok));

        // Bob is notified, then polls and finds the message.
        bob_conn.next_notification().await.expect("push");
        let resp = bob_conn
            .request(&encode_request(&Request::Poll { device: bob }))
            .await
            .unwrap();
        assert_eq!(
            decode_response(&resp),
            Some(Response::Delivered {
                from: 0,
                messages: vec![msg(&alice, 0x42)],
            })
        );
    }
}
