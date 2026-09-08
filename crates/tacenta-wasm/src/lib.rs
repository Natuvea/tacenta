//! The TypeScript head's WebAssembly module (decision 0090).
//!
//! What crosses the boundary is small on purpose: JavaScript fetches the
//! service document (its own `fetch`, under the browser's TLS), opens a
//! WebSocket per service when asked, and pushes the bytes it receives into
//! a [`Channel`]; everything above the bytes, the four protocols, the
//! sessions, the persisted state, is the same Rust the native clients run.
//!
//! The JavaScript side supplies one function, `open(url, channel)`, which
//! must return an object with `send(bytes)` and `close()`. Bytes the socket
//! receives go to `channel.push(bytes)`; when the socket closes,
//! `channel.close()`.
//!
//! A handle built with [`TacentaHandle::connect`] holds the document to the
//! same rule the native client applies (`Tacenta::from_discovered`): over
//! an https origin it may not turn TLS off, name another domain, or offer
//! a carriage that is not `wss://` on that domain. A page's credentials
//! therefore cannot be steered by a compromised gateway any more than a
//! native client's can. [`TacentaHandle::from_document`] is the path for a
//! document the caller vouches for.

use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;

use futures_util::FutureExt;
use futures_util::future::{LocalBoxFuture, Shared};
use std::sync::Arc;
use std::task::{Context, Poll};

use js_sys::{Function, Reflect, Uint8Array};
use tacenta_client::{
    ClientTls, Connecting, Connector, DefaultClient, DeviceAddr, ServiceDocument, Tacenta,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use wasm_bindgen::prelude::*;

/// The receiving end of one socket, handed to JavaScript: push what the
/// socket receives, close when it closes.
#[wasm_bindgen]
pub struct Channel {
    incoming: mpsc::Sender<Option<Vec<u8>>>,
}

/// How many messages may wait unread on one socket. The browser offers no
/// receive backpressure, so this is the bound on what a server can make a
/// page hold; a reader that falls this far behind is a closed connection.
const INBOUND_QUEUE: usize = 1024;

#[wasm_bindgen]
impl Channel {
    /// Bytes the socket received. Taken by value: wasm-bindgen builds the
    /// vector straight from the JavaScript array, one copy rather than two.
    pub fn push(&self, bytes: Vec<u8>) {
        if self.incoming.try_send(Some(bytes)).is_err() {
            // Full, or the reader is gone: end the stream rather than grow.
            // Dropping the sender is the close the reader sees.
            let _ = self.incoming.try_send(None);
        }
    }

    /// The socket closed.
    pub fn close(&self) {
        let _ = self.incoming.try_send(None);
    }
}

/// A byte stream over a JavaScript socket: reads drain what the
/// [`Channel`] was pushed, writes are queued for a pump that calls the
/// socket's `send`. Both halves are plain queues, so the stream is `Send`
/// even though the JavaScript objects behind it are not.
struct JsStream {
    incoming: mpsc::Receiver<Option<Vec<u8>>>,
    /// The last message received, and how much of it readers have taken:
    /// a cursor rather than a drain, so reading a frame's four-byte length
    /// prefix does not move the whole body.
    pending: Vec<u8>,
    taken: usize,
    eof: bool,
    outgoing: mpsc::UnboundedSender<Option<Vec<u8>>>,
}

impl AsyncRead for JsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if self.taken < self.pending.len() {
                let rest = &self.pending[self.taken..];
                let n = rest.len().min(buf.remaining());
                buf.put_slice(&rest[..n]);
                self.taken += n;
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            match std::task::ready!(self.incoming.poll_recv(cx)) {
                Some(Some(bytes)) => {
                    self.pending = bytes;
                    self.taken = 0;
                }
                Some(None) | None => self.eof = true,
            }
        }
    }
}

impl AsyncWrite for JsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.outgoing
            .send(Some(buf.to_vec()))
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "socket closed"))?;
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let _ = self.outgoing.send(None);
        Poll::Ready(Ok(()))
    }
}

/// The JavaScript `open` function, kept on this thread (it is not `Send`)
/// and reached through a request queue so the [`Connector`] can be.
struct JsOpener {
    open: Function,
    base: String,
}

impl JsOpener {
    /// Open one socket: call `open(url, channel)`, wire its `send` and
    /// `close` to a pump on the event loop, return the stream.
    fn open(&self, service: &str) -> std::io::Result<JsStream> {
        let url = format!("{}/{service}", self.base.trim_end_matches('/'));
        let (in_tx, in_rx) = mpsc::channel(INBOUND_QUEUE);
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Option<Vec<u8>>>();
        let channel = Channel { incoming: in_tx };
        let socket = self
            .open
            .call2(&JsValue::NULL, &JsValue::from_str(&url), &channel.into())
            .map_err(|e| js_err("open", e))?;
        let send = Reflect::get(&socket, &JsValue::from_str("send"))
            .ok()
            .and_then(|f| f.dyn_into::<Function>().ok())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "open() returned no send()",
                )
            })?;
        let close = Reflect::get(&socket, &JsValue::from_str("close"))
            .ok()
            .and_then(|f| f.dyn_into::<Function>().ok());
        wasm_bindgen_futures::spawn_local(async move {
            while let Some(item) = out_rx.recv().await {
                match item {
                    Some(bytes) => {
                        let array = Uint8Array::from(bytes.as_slice());
                        if send.call1(&socket, &array).is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            if let Some(close) = close {
                let _ = close.call0(&socket);
            }
        });
        Ok(JsStream {
            incoming: in_rx,
            pending: Vec::new(),
            taken: 0,
            eof: false,
            outgoing: out_tx,
        })
    }
}

/// The [`Connector`] the handle dials through: requests cross to the
/// thread-bound opener over a queue, answered by a pump on the event loop.
struct JsConnector {
    requests: mpsc::UnboundedSender<(
        String,
        tokio::sync::oneshot::Sender<std::io::Result<JsStream>>,
    )>,
}

impl JsConnector {
    fn new(open: Function, base: String) -> JsConnector {
        let (tx, mut rx) = mpsc::unbounded_channel::<(String, tokio::sync::oneshot::Sender<_>)>();
        let opener = JsOpener { open, base };
        wasm_bindgen_futures::spawn_local(async move {
            while let Some((service, reply)) = rx.recv().await {
                let _ = reply.send(opener.open(&service));
            }
        });
        JsConnector { requests: tx }
    }
}

impl Connector for JsConnector {
    fn open(&self, service: &str) -> Connecting {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let sent = self.requests.send((service.to_owned(), reply_tx));
        Box::pin(async move {
            sent.map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "opener gone"))?;
            let stream = reply_rx.await.map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "opener dropped the request")
            })??;
            Ok(Box::new(stream) as Box<dyn tacenta_client::ByteStream>)
        })
    }
}

fn js_err(what: &str, e: JsValue) -> std::io::Error {
    std::io::Error::other(format!(
        "{what}: {}",
        e.as_string().unwrap_or_else(|| format!("{e:?}"))
    ))
}

/// A thrown value JavaScript can branch on: a real `Error` (so it carries a
/// stack and `instanceof Error` holds even where the TypeScript head has
/// not wrapped it) named `TacentaError`, with a `kind` property that is one
/// of the kinds every head shares (decision 0090); the TypeScript head turns
/// it into its own `TacentaError` class.
fn err_kind(kind: &str, message: impl std::fmt::Display) -> JsValue {
    let out = js_sys::Error::new(&message.to_string());
    out.set_name("TacentaError");
    let _ = Reflect::set(&out, &JsValue::from_str("kind"), &JsValue::from_str(kind));
    out.into()
}

/// The client's error, with its kind.
fn err(e: tacenta_client::Error) -> JsValue {
    err_kind(e.kind().as_str(), e)
}

/// One tenant's handle: the API key, the service document JavaScript
/// fetched, and the socket opener.
#[wasm_bindgen]
pub struct TacentaHandle {
    inner: Tacenta,
    #[cfg(feature = "harness")]
    connector: Arc<JsConnector>,
}

impl TacentaHandle {
    /// The connector for a document, at its `ws` base URL.
    fn connector_for(doc: &ServiceDocument, open: Function) -> Result<Arc<JsConnector>, JsValue> {
        let base = doc.ws.clone().ok_or_else(|| {
            err_kind(
                "discovery",
                "the service document offers no websocket carriage",
            )
        })?;
        Ok(Arc::new(JsConnector::new(open, base)))
    }

    fn finish(handle: Tacenta, connector: Arc<JsConnector>) -> TacentaHandle {
        let inner = handle.with_connector(connector.clone());
        #[cfg(not(feature = "harness"))]
        drop(connector);
        TacentaHandle {
            inner,
            #[cfg(feature = "harness")]
            connector,
        }
    }
}

/// The document's addresses, ports only: nothing here dials one, the
/// connector opens sockets by service name.
fn placeholder_endpoints(doc: &ServiceDocument) -> Result<tacenta_client::Endpoints, JsValue> {
    let one = |entry: &str| -> Result<std::net::SocketAddr, JsValue> {
        if let Ok(addr) = entry.parse() {
            return Ok(addr);
        }
        let port: u16 = entry
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .ok_or_else(|| err_kind("discovery", format!("no port in {entry}")))?;
        Ok(std::net::SocketAddr::from(([0, 0, 0, 0], port)))
    };
    Ok(tacenta_client::Endpoints {
        directory: one(&doc.directory)?,
        relay: one(&doc.relay)?,
        accounts: one(&doc.accounts)?,
        provisioning: one(&doc.provisioning)?,
    })
}

#[wasm_bindgen]
impl TacentaHandle {
    /// Build a handle from the document fetched from `document_url`, holding
    /// the document to what a document from that origin may say (the native
    /// client's rule), and reaching the services through `open` at the
    /// document's `ws` base URL.
    pub async fn connect(
        api_key: String,
        document_url: String,
        document_json: String,
        open: Function,
    ) -> Result<TacentaHandle, JsValue> {
        let doc: ServiceDocument =
            serde_json::from_str(&document_json).map_err(|e| err_kind("discovery", e))?;
        // The guarded path: the same check, error text and tests as native.
        let guarded =
            Tacenta::from_discovered(&api_key, &document_url, &doc, &ClientTls::web_pki())
                .await
                .map_err(err)?;
        let connector = TacentaHandle::connector_for(&doc, open)?;
        Ok(TacentaHandle::finish(guarded, connector))
    }

    /// Build a handle from a document the caller vouches for, with no
    /// origin check: the counterpart of the native `from_document`. The one
    /// thing still refused is a plaintext carriage (`ws://`) to anything but
    /// loopback, unless `allow_plaintext` says the caller means it: on this
    /// head the document's `tls` field is inert (the browser does TLS), so
    /// the carriage's scheme is the only thing standing between the API key
    /// and the wire.
    #[wasm_bindgen(js_name = fromDocument)]
    pub fn from_document(
        api_key: String,
        document_json: String,
        open: Function,
        allow_plaintext: bool,
    ) -> Result<TacentaHandle, JsValue> {
        let doc: ServiceDocument =
            serde_json::from_str(&document_json).map_err(|e| err_kind("discovery", e))?;
        if doc.version != tacenta_discovery::VERSION {
            return Err(err_kind(
                "discovery",
                format!(
                    "service document version {} is not one this client reads",
                    doc.version
                ),
            ));
        }
        if let Some(ws) = doc.ws.as_deref()
            && !allow_plaintext
            && !ws.starts_with("wss://")
            && !is_loopback_ws(ws)
        {
            return Err(err_kind(
                "discovery",
                "the document's carriage is plaintext and not on loopback; pass allowPlaintext to accept it",
            ));
        }
        let connector = TacentaHandle::connector_for(&doc, open)?;
        let handle = Tacenta::from_endpoints(&api_key, placeholder_endpoints(&doc)?, None);
        Ok(TacentaHandle::finish(handle, connector))
    }

    /// Create a tenant on the server behind this handle and return its API
    /// key: the harness's way to start from an empty server. Not built into
    /// the published package.
    #[cfg(feature = "harness")]
    #[wasm_bindgen(js_name = signUpTenant)]
    pub async fn sign_up_tenant(
        &self,
        username: String,
        email: String,
        password: String,
    ) -> Result<String, JsValue> {
        use tacenta_accounts::AccountResponse;
        let stream = self
            .connector
            .open("accounts")
            .await
            .map_err(|e| err_kind("network", e))?;
        let mut accounts = tacenta_transport::AccountConnection::establish(stream)
            .await
            .map_err(|e| err_kind("network", e))?;
        match accounts
            .sign_up_tenant(&username, &email, &password)
            .await
            .map_err(|e| err_kind("network", e))?
        {
            AccountResponse::TenantCreated { api_key, .. } => Ok(api_key),
            AccountResponse::ServerError => {
                Err(err_kind("serverFailure", "tenant signup: server error"))
            }
            AccountResponse::RateLimited => {
                Err(err_kind("rateLimited", "tenant signup: rate limited"))
            }
            other => Err(err_kind(
                "signUpRefused",
                format!("tenant signup refused: {other:?}"),
            )),
        }
    }

    /// Create a user in this tenant.
    #[wasm_bindgen(js_name = signUp)]
    pub async fn sign_up(&self, username: String, password: String) -> Result<(), JsValue> {
        self.inner.sign_up(&username, &password).await.map_err(err)
    }

    /// Sign a user in on `device` with a fresh identity.
    #[wasm_bindgen(js_name = signIn)]
    pub async fn sign_in(
        &self,
        username: String,
        password: String,
        device: u8,
    ) -> Result<Client, JsValue> {
        let client = self
            .inner
            .sign_in_device(&username, &password, device)
            .await
            .map_err(err)?;
        Ok(Client::wrap(client))
    }

    /// Sign in resuming persisted state from `exportState`.
    #[wasm_bindgen(js_name = signInWithState)]
    pub async fn sign_in_with_state(
        &self,
        username: String,
        password: String,
        device: u8,
        state: &[u8],
    ) -> Result<Client, JsValue> {
        let client = self
            .inner
            .sign_in_with_state(&username, &password, device, state)
            .await
            .map_err(err)?;
        Ok(Client::wrap(client))
    }
}

/// A signed-in client. Methods are asynchronous and take turns on the
/// underlying client; JavaScript sees promises.
#[wasm_bindgen]
pub struct Client {
    inner: Rc<tokio::sync::Mutex<DefaultClient>>,
    address: String,
    /// Pinged when mail may be waiting; `receive` waits on it outside the
    /// lock, so a `send` goes through while a receive is pending.
    mail: tacenta_client::MailSignal,
    /// The one `receive` in flight, shared by every caller awaiting it, so
    /// two outstanding promises see the same batches rather than taking
    /// turns, and an abandoned promise's batch waits for the next call.
    inbound: Rc<RefCell<Option<Inbound>>>,
}

type Inbound = Shared<LocalBoxFuture<'static, Result<Vec<Message>, JsValue>>>;

impl Client {
    fn wrap(client: DefaultClient) -> Client {
        let address = format!("{}/{}", client.address().user, client.address().device);
        Client {
            mail: client.mail(),
            inner: Rc::new(tokio::sync::Mutex::new(client)),
            address,
            inbound: Rc::new(RefCell::new(None)),
        }
    }

    /// Poll under the lock, wait for mail outside it, so a send on the same
    /// client goes through while a receive is pending.
    async fn next_batch(
        inner: Rc<tokio::sync::Mutex<DefaultClient>>,
        mail: tacenta_client::MailSignal,
    ) -> Result<Vec<Message>, JsValue> {
        loop {
            let messages = inner.lock().await.drain().await.map_err(err)?;
            if !messages.is_empty() {
                return Ok(messages
                    .into_iter()
                    .map(|m| Message {
                        from: format!("{}/{}", m.from.user, m.from.device),
                        plaintext: m.plaintext,
                    })
                    .collect());
            }
            mail.wait().await;
        }
    }
}

/// A received message, as JavaScript sees it.
#[wasm_bindgen(getter_with_clone)]
#[derive(Clone)]
pub struct Message {
    pub from: String,
    pub plaintext: Vec<u8>,
}

#[wasm_bindgen]
impl Client {
    /// This client's address, `user/device`.
    pub fn address(&self) -> String {
        self.address.clone()
    }

    /// What the sign-in found: `"fresh"`, `"resumed"` or
    /// `"sessionsDiscarded"` (the last only where a rollback can be caught).
    #[wasm_bindgen(js_name = restoreOutcome)]
    pub async fn restore_outcome(&self) -> String {
        self.inner
            .lock()
            .await
            .restore_outcome()
            .as_str()
            .to_owned()
    }

    /// Look a username up in the tenant; the address to send to, or
    /// `undefined`.
    pub async fn find(&self, username: String) -> Result<Option<String>, JsValue> {
        let inner = self.inner.clone();
        let mut client = inner.lock().await;
        let found = client.find(&username).await.map_err(err)?;
        Ok(found.map(|c| format!("{}/{}", c.address.user, c.address.device)))
    }

    /// Send `plaintext` to `to` (`user/device`).
    pub async fn send(&self, to: String, plaintext: &[u8]) -> Result<(), JsValue> {
        let to = parse_address(&to)?;
        let inner = self.inner.clone();
        let mut client = inner.lock().await;
        client.send(&to, plaintext).await.map_err(err)
    }

    /// Fetch and decrypt what is waiting.
    pub async fn receive(&self) -> Result<Vec<Message>, JsValue> {
        // One receive in flight per client, shared by whoever awaits it.
        let pending = {
            let mut slot = self.inbound.borrow_mut();
            // A finished error nobody collected is not this call's answer.
            if slot
                .as_ref()
                .is_some_and(|pending| matches!(pending.peek(), Some(Err(_))))
            {
                *slot = None;
            }
            match slot.as_ref() {
                Some(pending) => pending.clone(),
                None => {
                    let pending: Inbound = Self::next_batch(self.inner.clone(), self.mail.clone())
                        .boxed_local()
                        .shared();
                    *slot = Some(pending.clone());
                    pending
                }
            }
        };
        let batch = pending.await;
        // Delivered: the next call starts a fresh wait.
        let mut slot = self.inbound.borrow_mut();
        if slot
            .as_ref()
            .is_some_and(|pending| pending.peek().is_some())
        {
            *slot = None;
        }
        batch
    }

    /// The identity and live sessions, to persist and resume with
    /// `signInWithState`.
    #[wasm_bindgen(js_name = exportState)]
    pub async fn export_state(&self) -> Result<Vec<u8>, JsValue> {
        let inner = self.inner.clone();
        let client = inner.lock().await;
        client.export_state().await.map_err(err)
    }
}

/// Whether a `ws://` URL points at this machine: the development gateway.
fn is_loopback_ws(ws: &str) -> bool {
    let Some(rest) = ws.strip_prefix("ws://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or("");
    let host = authority
        .strip_prefix('[')
        .and_then(|h| h.split(']').next())
        .unwrap_or_else(|| authority.split(':').next().unwrap_or(""));
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn parse_address(s: &str) -> Result<DeviceAddr, JsValue> {
    let (user, device) = s
        .rsplit_once('/')
        .ok_or_else(|| err_kind("invalidArgument", "an address is user/device"))?;
    let device: u32 = device
        .parse()
        .map_err(|_| err_kind("invalidArgument", "an address is user/device"))?;
    if !(1..=255).contains(&device) {
        return Err(err_kind("invalidArgument", "a device number is 1 to 255"));
    }
    Ok(DeviceAddr::new(user, device))
}
