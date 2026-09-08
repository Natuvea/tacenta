//! How a client reaches the four services: TCP (plain or under TLS), or the
//! WebSocket carriage (decision 0090). One value, threaded through
//! every connect and reconnect, so the protocol code never knows which.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use tacenta_transport::{
    AccountConnection, ClientTls, Connection, DirConnection, ProvisionConnection,
};

/// A byte stream a service can be spoken over.
pub trait ByteStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync> ByteStream for T {}

/// The future a [`Connector`] returns.
pub type Connecting = Pin<Box<dyn Future<Output = std::io::Result<Box<dyn ByteStream>>> + Send>>;

/// A caller-supplied way of reaching the four services: given a service
/// name (`directory`, `relay`, `accounts`, `provisioning`), open a byte
/// stream to it. This is how a host that owns the sockets, the browser
/// above all, lends them to the client: the WebAssembly head implements it
/// with a WebSocket per service opened from JavaScript (decision 0090). The protocol spoken over the stream is unchanged.
pub trait Connector: Send + Sync {
    fn open(&self, service: &str) -> Connecting;
}

// On wasm the native arms are compiled out, so their fields go unread there.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
#[derive(Clone)]
pub(crate) enum Dialer {
    /// The service's own TCP port, with the certificate name and trust for
    /// TLS, or `None` for a plaintext development server.
    Tcp { trust: Option<(String, ClientTls)> },
    /// `{base}/{service}` over WebSocket; `wss://` is checked under `tls`
    /// presenting the URL's host. The addresses the caller passes are
    /// ignored: the gateway dials the services.
    WebSocket { base: String, tls: ClientTls },
    /// Streams the caller opens; the addresses are ignored.
    Custom(Arc<dyn Connector>),
}

/// TCP is a native affair; a browser build reaches the services only
/// through a [`Connector`] or the WebSocket carriage.
#[cfg(target_arch = "wasm32")]
fn no_tcp<T>() -> std::io::Result<T> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "TCP is not available on this target; use the websocket carriage or a Connector",
    ))
}

impl Dialer {
    pub(crate) fn tcp(trust: Option<(&str, &ClientTls)>) -> Dialer {
        Dialer::Tcp {
            trust: trust.map(|(name, tls)| (name.to_owned(), tls.clone())),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn url(base: &str, service: &str) -> String {
        format!("{}/{service}", base.trim_end_matches('/'))
    }

    pub(crate) async fn accounts(&self, addr: SocketAddr) -> std::io::Result<AccountConnection> {
        match self {
            Dialer::Custom(connector) => {
                let stream = connector.open("accounts").await?;
                AccountConnection::establish(stream).await
            }
            #[cfg(not(target_arch = "wasm32"))]
            Dialer::Tcp {
                trust: Some((name, tls)),
            } => AccountConnection::connect_tls(addr, name, tls).await,
            #[cfg(not(target_arch = "wasm32"))]
            Dialer::Tcp { trust: None } => AccountConnection::connect(addr).await,
            #[cfg(not(target_arch = "wasm32"))]
            Dialer::WebSocket { base, tls } => {
                AccountConnection::connect_ws(&Dialer::url(base, "accounts"), tls).await
            }
            #[cfg(target_arch = "wasm32")]
            Dialer::Tcp { .. } | Dialer::WebSocket { .. } => {
                let _ = addr;
                no_tcp()
            }
        }
    }

    pub(crate) async fn provisioning(
        &self,
        addr: SocketAddr,
    ) -> std::io::Result<ProvisionConnection> {
        match self {
            Dialer::Custom(connector) => {
                let stream = connector.open("provisioning").await?;
                ProvisionConnection::establish(stream).await
            }
            #[cfg(not(target_arch = "wasm32"))]
            Dialer::Tcp {
                trust: Some((name, tls)),
            } => ProvisionConnection::connect_tls(addr, name, tls).await,
            #[cfg(not(target_arch = "wasm32"))]
            Dialer::Tcp { trust: None } => ProvisionConnection::connect(addr).await,
            #[cfg(not(target_arch = "wasm32"))]
            Dialer::WebSocket { base, tls } => {
                ProvisionConnection::connect_ws(&Dialer::url(base, "provisioning"), tls).await
            }
            #[cfg(target_arch = "wasm32")]
            Dialer::Tcp { .. } | Dialer::WebSocket { .. } => {
                let _ = addr;
                no_tcp()
            }
        }
    }

    pub(crate) async fn directory(&self, addr: SocketAddr) -> std::io::Result<DirConnection> {
        match self {
            Dialer::Custom(connector) => {
                let stream = connector.open("directory").await?;
                DirConnection::establish(stream).await
            }
            #[cfg(not(target_arch = "wasm32"))]
            Dialer::Tcp {
                trust: Some((name, tls)),
            } => DirConnection::connect_tls(addr, name, tls).await,
            #[cfg(not(target_arch = "wasm32"))]
            Dialer::Tcp { trust: None } => DirConnection::connect(addr).await,
            #[cfg(not(target_arch = "wasm32"))]
            Dialer::WebSocket { base, tls } => {
                DirConnection::connect_ws(&Dialer::url(base, "directory"), tls).await
            }
            #[cfg(target_arch = "wasm32")]
            Dialer::Tcp { .. } | Dialer::WebSocket { .. } => {
                let _ = addr;
                no_tcp()
            }
        }
    }

    pub(crate) async fn relay(
        &self,
        addr: SocketAddr,
        device: &tacenta_relay::DeviceAddr,
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
        signal: Arc<tokio::sync::Notify>,
    ) -> std::io::Result<Connection> {
        match self {
            Dialer::Custom(connector) => {
                let stream = connector.open("relay").await?;
                Connection::establish_with_signal(stream, device, sign, signal).await
            }
            #[cfg(not(target_arch = "wasm32"))]
            Dialer::Tcp {
                trust: Some((name, tls)),
            } => {
                Connection::connect_as_tls_with_signal(addr, name, tls, device, sign, signal).await
            }
            #[cfg(not(target_arch = "wasm32"))]
            Dialer::Tcp { trust: None } => {
                Connection::connect_as_with_signal(addr, device, sign, signal).await
            }
            #[cfg(not(target_arch = "wasm32"))]
            Dialer::WebSocket { base, tls } => {
                Connection::connect_as_ws_with_signal(
                    &Dialer::url(base, "relay"),
                    tls,
                    device,
                    sign,
                    signal,
                )
                .await
            }
            #[cfg(target_arch = "wasm32")]
            Dialer::Tcp { .. } | Dialer::WebSocket { .. } => {
                let _ = (addr, device, sign, signal);
                no_tcp()
            }
        }
    }
}
