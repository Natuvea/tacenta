//! A TCP transport for device provisioning: a signed-in client binds its
//! device's identity into the directory under its account's messaging handle.
//!
//! Provisioning is the bridge between the account layer and the directory. It
//! needs three things no single crate owns — a valid session (accounts),
//! proof the device holds its identity key (crypto), and the directory write —
//! so the transport defines a [`Provisioner`] trait and delegates all of it to
//! an implementor (the server), staying crypto- and account-free itself.
//!
//! On connect the server issues one challenge, exactly as the directory does;
//! the client signs it with the device identity key as proof of possession. A
//! request carries the session token that authorises the handle, so a client
//! can only provision a device under its own username.

use crate::{read_frame, write_frame};
// Arc appears only in the native-only serve functions.
#[cfg(not(target_arch = "wasm32"))]
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
#[cfg(not(target_arch = "wasm32"))]
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

/// A request to provision a device: bind `identity` + `bundle` into the
/// directory under the handle the `session_token` authorises. `possession_sig`
/// is the identity key's signature over the connection challenge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisionRequest {
    pub session_token: String,
    pub device: u32,
    pub identity: Vec<u8>,
    pub bundle: Vec<u8>,
    pub possession_sig: Vec<u8>,
}

/// The outcome of a provisioning attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProvisionOutcome {
    /// The device was bound; carries the directory handle it was bound under.
    Provisioned { handle: String },
    /// The session token was unknown (or expired).
    BadSession,
    /// The signature did not prove possession of the identity key.
    PossessionFailed,
    /// Trust on first use refused it: the handle is already bound to a
    /// different identity key.
    Rejected,
    /// The server could not process the request (a backend failure). Transient;
    /// nothing was bound.
    ServerError,
}

/// Provides the two things the transport cannot: a fresh challenge, and the
/// account-authenticated, possession-verified directory write. The server
/// implements this (it alone holds the accounts store, the crypto, and the
/// directory); the transport calls it.
pub trait Provisioner: Send + Sync + 'static {
    /// A fresh, unpredictable challenge for one connection.
    fn challenge(&self) -> Vec<u8>;

    /// Validate the session, verify `request.possession_sig` over `challenge`,
    /// and bind the device into the directory under the session's handle. Async
    /// because a database-backed account store is async; the returned future is
    /// `Send` so a connection can be served on a spawned task.
    fn provision(
        &self,
        request: &ProvisionRequest,
        challenge: &[u8],
    ) -> impl std::future::Future<Output = ProvisionOutcome> + Send;
}

fn put_u32(out: &mut Vec<u8>, n: u32) {
    out.extend_from_slice(&n.to_be_bytes());
}

fn take_u32(bytes: &[u8]) -> Option<(u32, &[u8])> {
    let (head, rest) = bytes.split_at_checked(4)?;
    Some((u32::from_be_bytes(head.try_into().ok()?), rest))
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, u32::try_from(bytes.len()).expect("field fits u32"));
    out.extend_from_slice(bytes);
}

fn take_bytes(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = take_u32(bytes)?;
    rest.split_at_checked(len as usize)
}

fn take_str(bytes: &[u8]) -> Option<(String, &[u8])> {
    let (b, rest) = take_bytes(bytes)?;
    Some((String::from_utf8(b.to_vec()).ok()?, rest))
}

/// Encode a provisioning request.
pub fn encode_provision_request(request: &ProvisionRequest) -> Vec<u8> {
    let mut out = Vec::new();
    put_bytes(&mut out, request.session_token.as_bytes());
    put_u32(&mut out, request.device);
    put_bytes(&mut out, &request.identity);
    put_bytes(&mut out, &request.bundle);
    put_bytes(&mut out, &request.possession_sig);
    out
}

/// Decode a provisioning request; `None` on any malformation.
pub fn decode_provision_request(bytes: &[u8]) -> Option<ProvisionRequest> {
    let (session_token, rest) = take_str(bytes)?;
    let (device, rest) = take_u32(rest)?;
    let (identity, rest) = take_bytes(rest)?;
    let (bundle, rest) = take_bytes(rest)?;
    let (possession_sig, rest) = take_bytes(rest)?;
    rest.is_empty().then(|| ProvisionRequest {
        session_token,
        device,
        identity: identity.to_vec(),
        bundle: bundle.to_vec(),
        possession_sig: possession_sig.to_vec(),
    })
}

/// Encode a provisioning outcome. Tags: 1 = Provisioned, 2 = BadSession,
/// 3 = PossessionFailed, 4 = Rejected.
pub fn encode_provision_outcome(outcome: &ProvisionOutcome) -> Vec<u8> {
    let mut out = Vec::new();
    match outcome {
        ProvisionOutcome::Provisioned { handle } => {
            out.push(1);
            put_bytes(&mut out, handle.as_bytes());
        }
        ProvisionOutcome::BadSession => out.push(2),
        ProvisionOutcome::PossessionFailed => out.push(3),
        ProvisionOutcome::Rejected => out.push(4),
        ProvisionOutcome::ServerError => out.push(5),
    }
    out
}

/// Decode a provisioning outcome; `None` on any malformation.
pub fn decode_provision_outcome(bytes: &[u8]) -> Option<ProvisionOutcome> {
    let (tag, rest) = bytes.split_first()?;
    match tag {
        1 => {
            let (handle, rest) = take_str(rest)?;
            rest.is_empty()
                .then_some(ProvisionOutcome::Provisioned { handle })
        }
        2 => rest.is_empty().then_some(ProvisionOutcome::BadSession),
        3 => rest
            .is_empty()
            .then_some(ProvisionOutcome::PossessionFailed),
        4 => rest.is_empty().then_some(ProvisionOutcome::Rejected),
        5 => rest.is_empty().then_some(ProvisionOutcome::ServerError),
        _ => None,
    }
}

/// Serve one provisioning connection: issue a challenge, then answer requests
/// until the client disconnects.
#[cfg(not(target_arch = "wasm32"))]
async fn serve_provision_connection<S, P>(
    mut stream: S,
    provisioner: Arc<P>,
    idle: std::time::Duration,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
    P: Provisioner,
{
    let challenge = provisioner.challenge();
    write_frame(&mut stream, &challenge).await?;
    loop {
        // A client that connects and falls silent is closed.
        let Some(frame) = crate::read_frame_within(&mut stream, idle).await? else {
            return Ok(());
        };
        let Some(request) = decode_provision_request(&frame) else {
            return Ok(());
        };
        let outcome = provisioner.provision(&request, &challenge).await;
        write_frame(&mut stream, &encode_provision_outcome(&outcome)).await?;
    }
}

/// Accept provisioning connections forever, serving each against the shared
/// provisioner. Returns only on a fatal accept error.
#[cfg(not(target_arch = "wasm32"))]
pub async fn serve_provisioning<P: Provisioner>(
    listener: TcpListener,
    provisioner: Arc<P>,
) -> std::io::Result<()> {
    serve_provisioning_with_limits(listener, provisioner, crate::ServeLimits::default()).await
}

/// [`serve_provisioning`] under explicit [`ServeLimits`](crate::ServeLimits).
#[cfg(not(target_arch = "wasm32"))]
pub async fn serve_provisioning_with_limits<P: Provisioner>(
    listener: TcpListener,
    provisioner: Arc<P>,
    limits: crate::ServeLimits,
) -> std::io::Result<()> {
    crate::accept_loop(listener, limits, move |stream, _peer| {
        let provisioner = provisioner.clone();
        async move {
            let _ = serve_provision_connection(stream, provisioner, limits.idle).await;
        }
    })
    .await
}

/// Like [`serve_provisioning`], but each connection is wrapped in TLS first.
#[cfg(not(target_arch = "wasm32"))]
pub async fn serve_provisioning_tls<P: Provisioner>(
    listener: TcpListener,
    provisioner: Arc<P>,
    tls: crate::ServerTls,
) -> std::io::Result<()> {
    serve_provisioning_tls_with_limits(listener, provisioner, tls, crate::ServeLimits::default())
        .await
}

/// [`serve_provisioning_tls`] under explicit [`ServeLimits`](crate::ServeLimits).
#[cfg(not(target_arch = "wasm32"))]
pub async fn serve_provisioning_tls_with_limits<P: Provisioner>(
    listener: TcpListener,
    provisioner: Arc<P>,
    tls: crate::ServerTls,
    limits: crate::ServeLimits,
) -> std::io::Result<()> {
    crate::accept_loop(listener, limits, move |tcp, _peer| {
        let provisioner = provisioner.clone();
        let acceptor = tls.acceptor.clone();
        async move {
            if let Ok(stream) = acceptor.accept(tcp).await {
                let _ = serve_provision_connection(stream, provisioner, limits.idle).await;
            }
        }
    })
    .await
}

/// A client connection to a provisioning server. The connection's challenge
/// (issued once, on connect) is what the device identity key signs.
pub struct ProvisionConnection {
    read: Box<dyn AsyncRead + Unpin + Send + Sync>,
    write: Box<dyn AsyncWrite + Unpin + Send + Sync>,
    challenge: Vec<u8>,
}

impl ProvisionConnection {
    /// Connect over TCP and receive the connection challenge.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect(addr: impl ToSocketAddrs) -> std::io::Result<ProvisionConnection> {
        let stream = TcpStream::connect(addr).await?;
        ProvisionConnection::establish(stream).await
    }

    /// Connect over TLS to a server presenting `server_name`, then receive the
    /// connection challenge.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect_tls(
        addr: impl ToSocketAddrs,
        server_name: &str,
        tls: &crate::ClientTls,
    ) -> std::io::Result<ProvisionConnection> {
        let tcp = TcpStream::connect(addr).await?;
        let stream = tls.wrap(server_name, tcp).await?;
        ProvisionConnection::establish(stream).await
    }

    /// Receive the connection challenge over an already-connected `stream`.
    pub async fn establish<S>(mut stream: S) -> std::io::Result<ProvisionConnection>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
    {
        let challenge = read_frame(&mut stream).await?.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no challenge")
        })?;
        let (read, write) = tokio::io::split(stream);
        Ok(ProvisionConnection {
            read: Box::new(read),
            write: Box::new(write),
            challenge,
        })
    }

    /// Provision `device` under the account the `session_token` authorises.
    /// `sign` signs the connection challenge with the device identity's
    /// private key (the caller owns the identity key and the signing crypto).
    pub async fn provision(
        &mut self,
        session_token: &str,
        device: u32,
        identity: Vec<u8>,
        bundle: Vec<u8>,
        sign: impl FnOnce(&[u8]) -> Vec<u8>,
    ) -> std::io::Result<ProvisionOutcome> {
        let possession_sig = sign(&self.challenge);
        let request = ProvisionRequest {
            session_token: session_token.to_owned(),
            device,
            identity,
            bundle,
            possession_sig,
        };
        write_frame(&mut self.write, &encode_provision_request(&request)).await?;
        let frame = read_frame(&mut self.read)
            .await?
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no response"))?;
        decode_provision_outcome(&frame).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "malformed response")
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let request = ProvisionRequest {
            session_token: "ses_abc".into(),
            device: 3,
            identity: vec![1, 2, 3],
            bundle: vec![4, 5],
            possession_sig: vec![6, 7, 8, 9],
        };
        assert_eq!(
            decode_provision_request(&encode_provision_request(&request)),
            Some(request),
        );
    }

    #[test]
    fn outcomes_round_trip() {
        for outcome in [
            ProvisionOutcome::Provisioned {
                handle: "acme/alice".into(),
            },
            ProvisionOutcome::BadSession,
            ProvisionOutcome::PossessionFailed,
            ProvisionOutcome::Rejected,
            ProvisionOutcome::ServerError,
        ] {
            assert_eq!(
                decode_provision_outcome(&encode_provision_outcome(&outcome)),
                Some(outcome),
            );
        }
    }
}
