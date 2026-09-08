//! TLS for the transport: server-authenticated encryption of the byte
//! stream both services already speak (decision record 0023).
//!
//! This wraps the connection, not the protocol. The framed relay and
//! directory protocols are unchanged — a TLS stream is just another
//! `AsyncRead + AsyncWrite`, so `serve_tls` / `connect_as_tls` reuse the
//! same `serve_connection` / `establish` paths as plain TCP. TLS protects
//! the transport (the metadata: who connects, the challenge/response, the
//! opaque ciphertext in flight) and authenticates the server to the client;
//! message *content* is already end-to-end encrypted underneath it.
//!
//! The `ring` crypto provider is used (lighter build than aws-lc-rs). It is
//! installed as the process default once, lazily.

use std::sync::{Arc, Once};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// Install the `ring` crypto provider as the process default, once. Ignores
/// the error returned when a provider is already installed.
fn ensure_provider() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A server's TLS identity: its certificate chain and private key, wrapped
/// as an acceptor to hand to [`serve_tls`](crate::serve_tls) /
/// [`serve_directory_tls`](crate::serve_directory_tls).
#[derive(Clone)]
pub struct ServerTls {
    pub(crate) acceptor: TlsAcceptor,
}

impl ServerTls {
    /// Build from a DER certificate chain and a PKCS#8 DER private key
    /// (each as raw bytes — the rustls types stay internal).
    pub fn from_der(
        cert_chain: Vec<Vec<u8>>,
        pkcs8_key: Vec<u8>,
    ) -> Result<ServerTls, rustls::Error> {
        let certs = cert_chain.into_iter().map(CertificateDer::from).collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_key));
        ServerTls::build(certs, key)
    }

    /// Build from PEM bytes: a certificate chain and a PKCS#8 private key.
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> std::io::Result<ServerTls> {
        let certs = rustls_pemfile::certs(&mut &cert_pem[..]).collect::<Result<Vec<_>, _>>()?;
        let key = rustls_pemfile::private_key(&mut &key_pem[..])?.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "no private key in PEM")
        })?;
        ServerTls::build(certs, key)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }

    fn build(
        certs: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<ServerTls, rustls::Error> {
        ensure_provider();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)?;
        Ok(ServerTls {
            acceptor: TlsAcceptor::from(Arc::new(config)),
        })
    }
}

/// A client's TLS trust: which server certificate(s) to accept. Use
/// [`ClientTls::trusting`] to pin a specific self-signed server certificate.
#[derive(Clone)]
pub struct ClientTls {
    pub(crate) connector: TlsConnector,
}

impl ClientTls {
    /// Trust the given certificate (DER bytes) as the one root: a self-signed
    /// server certificate, or a private CA's certificate, rather than the
    /// public web PKI. It is a trust anchor, not a pin: a leaf issued by a CA
    /// does not verify against itself, and a CA here admits every certificate
    /// it issues for the name the client asks for.
    pub fn trusting(cert_der: Vec<u8>) -> Result<ClientTls, rustls::Error> {
        ensure_provider();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(cert_der))?;
        Ok(ClientTls::with_roots(roots))
    }

    /// [`trusting`](Self::trusting) for PEM: every certificate in `pem`
    /// becomes a trust anchor, so a private CA's certificate, or a full chain
    /// pasted leaf-first, both work. This is how a service document carries a
    /// private trust root (`tacenta-discovery`'s `private-ca` mode).
    pub fn trusting_pem(pem: &[u8]) -> std::io::Result<ClientTls> {
        ensure_provider();
        let mut reader = pem;
        let mut roots = rustls::RootCertStore::empty();
        let mut count = 0;
        for cert in rustls_pemfile::certs(&mut reader) {
            let cert = cert?;
            roots
                .add(cert)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            count += 1;
        }
        if count == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no certificate in the PEM",
            ));
        }
        Ok(ClientTls::with_roots(roots))
    }

    /// Wrap an already-connected stream in TLS to a server presenting
    /// `server_name`, under this trust. The four `connect_tls` paths and the
    /// gateway's WebSocket carriage all reach TLS through here.
    pub async fn wrap<S>(
        &self,
        server_name: &str,
        stream: S,
    ) -> std::io::Result<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + use<S>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
    {
        let name =
            rustls::pki_types::ServerName::try_from(server_name.to_owned()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid server name")
            })?;
        self.connector.connect(name, stream).await
    }

    /// [`wrap`](Self::wrap) for a TCP stream, with the concrete TLS stream
    /// type, for a caller that stores it in an enum.
    pub async fn wrap_tcp(
        &self,
        server_name: &str,
        tcp: tokio::net::TcpStream,
    ) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
        let name =
            rustls::pki_types::ServerName::try_from(server_name.to_owned()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid server name")
            })?;
        self.connector.connect(name, tcp).await
    }

    /// Trust the public web PKI (Mozilla's CA root store) — for connecting to a
    /// hosted server whose certificate is from a public CA such as Let's
    /// Encrypt. This is the trust a client uses against `tacenta.com`.
    pub fn web_pki() -> ClientTls {
        ensure_provider();
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientTls::with_roots(roots)
    }

    fn with_roots(roots: rustls::RootCertStore) -> ClientTls {
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        ClientTls {
            connector: TlsConnector::from(Arc::new(config)),
        }
    }
}

/// The client trust a service document's `tls` mode calls for, presenting
/// `server_name`: `None` for plaintext, the web PKI, or the document's own
/// trust anchors. The gateway (dialling the services for the WebSocket
/// carriage) and the client crate both derive their trust through here.
pub fn trust_for(
    tls: &tacenta_discovery::Tls,
    server_name: &str,
) -> std::io::Result<Option<(String, ClientTls)>> {
    use tacenta_discovery::Tls;
    Ok(match tls {
        Tls::None => None,
        Tls::WebPki => Some((server_name.to_owned(), ClientTls::web_pki())),
        Tls::PrivateCa { trust_anchors_pem } => Some((
            server_name.to_owned(),
            ClientTls::trusting_pem(trust_anchors_pem.as_bytes())?,
        )),
    })
}
