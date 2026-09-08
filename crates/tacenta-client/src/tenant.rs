//! The tenant handle: the first layer of the SDK surface (decision 0090).
//!
//! An app holds one [`Tacenta`] per tenant. It is built from the API key and
//! the server's name, fetches the server's service document once to learn
//! where the four services are, and hands out signed-in
//! [`Client`](crate::Client)s. Nothing
//! above this layer sees a host or a port: the four `host:port` pairs a
//! sample would otherwise carry live in the document the server publishes at
//! `/.well-known/tacenta` (`tacenta-discovery` is the shared definition), and
//! a deployment that moves a service moves it there.
//!
//! The server is a parameter with a default, never a constant baked in: a
//! self-hosted deployment points the handle at itself.
//!
//! # What a document may and may not say
//!
//! A document fetched over `https://` arrives authenticated by the web PKI,
//! and the handle holds it to that: it may name services on the host it came
//! from or on subdomains of it, and it may ask for web-PKI or a private trust
//! root under such a name, but it may not turn TLS off and it may not send
//! the tenant's key and its users' passwords to some other domain. A
//! misconfigured or compromised gateway is therefore bounded to its own
//! domain, and cannot downgrade a client below the trust the caller
//! configured. The rule is deliberately the origin host and its subdomains,
//! not "the same registrable domain": deciding that without the public
//! suffix list admits every neighbour on a shared platform host, so a
//! deployment serves its document from the host its services are on, or an
//! ancestor of it (the shipped deployment uses the apex for both).
//!
//! A document fetched over `http://` has no authentication to hold it to, so
//! it is accepted only from loopback: the development server on the same
//! machine. Anywhere else, plaintext discovery would let one intercepted GET
//! redirect the credentials, and is refused; a caller that has a document
//! it vouches for by other means builds the handle from it with
//! [`Tacenta::from_document`].

use std::net::SocketAddr;
use std::sync::Arc;

use tacenta_discovery::{ServiceDocument, Tls, host_of};
use tacenta_transport::ClientTls;

use crate::dial::{Connector, Dialer};
use crate::{AccountConfig, DefaultClient, Error, Result, SecureStore};

/// The four services, resolved to socket addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoints {
    pub directory: SocketAddr,
    pub relay: SocketAddr,
    pub accounts: SocketAddr,
    pub provisioning: SocketAddr,
}

/// One tenant's handle on one server: the API key, where the services are,
/// and how the server is trusted. Cheap to clone; hold one per tenant.
#[derive(Clone)]
pub struct Tacenta {
    api_key: String,
    endpoints: Endpoints,
    /// The name the certificate presents and the trust to check it against,
    /// or `None` for a plaintext development server.
    trust: Option<(String, ClientTls)>,
    /// The trust the document itself arrived under: what a `wss://` carriage
    /// is checked against, since it terminates at the discovery origin
    /// rather than at the services.
    origin_tls: ClientTls,
    carriage: Carriage,
}

/// Whether the document offered a WebSocket carriage, and whether this
/// handle takes it.
#[derive(Clone)]
enum Carriage {
    /// No carriage offered: TCP only.
    Tcp,
    /// Offered at this base URL; the handle dials TCP.
    Offered(String),
    /// Offered at this base URL, and the handle dials through it.
    Active(String),
    /// The caller opens the streams (see [`Connector`]).
    Custom(Arc<dyn Connector>),
}

impl std::fmt::Debug for Carriage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Carriage::Tcp => f.write_str("Tcp"),
            Carriage::Offered(b) => f.debug_tuple("Offered").field(b).finish(),
            Carriage::Active(b) => f.debug_tuple("Active").field(b).finish(),
            Carriage::Custom(_) => f.write_str("Custom"),
        }
    }
}

/// Hand-written so the API key never reaches a log line: a `{:?}` on a handle
/// shows where it points and how it trusts the server, and a redaction where
/// the key would be.
impl std::fmt::Debug for Tacenta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tacenta")
            .field("server_name", &self.server_name())
            .field("endpoints", &self.endpoints)
            .field("tls", &self.is_tls())
            .field("carriage", &self.carriage)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

impl Tacenta {
    /// The hosted service.
    pub const DEFAULT_SERVER: &'static str = "tacenta.com";

    /// Connect to hosted Tacenta: fetch its service document over HTTPS and
    /// trust its certificate through the public web PKI.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect(api_key: &str) -> Result<Tacenta> {
        Tacenta::connect_to(api_key, Tacenta::DEFAULT_SERVER).await
    }

    /// Connect to the Tacenta server at `server` (a host name), fetching
    /// `https://{server}/.well-known/tacenta` with web-PKI trust.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect_to(api_key: &str, server: &str) -> Result<Tacenta> {
        let url = format!("https://{server}{}", tacenta_discovery::WELL_KNOWN_PATH);
        Tacenta::connect_via(api_key, &url, &ClientTls::web_pki()).await
    }

    /// Connect by fetching the service document at an explicit URL, with
    /// `tls` deciding the trust for an `https://` URL. This is the local
    /// development path (`http://127.0.0.1:4780/.well-known/tacenta`, the
    /// gateway's own port; `http://` is accepted from loopback only) and the
    /// path for a private certificate on the discovery host itself.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn connect_via(api_key: &str, url: &str, tls: &ClientTls) -> Result<Tacenta> {
        let doc = Tacenta::fetch_document(url, tls).await?;
        Tacenta::from_discovered(api_key, url, &doc, tls).await
    }

    /// Fetch and parse the service document at `url`, without building a
    /// handle: for a caller that caches documents. Pair it with
    /// [`from_discovered`](Self::from_discovered).
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn fetch_document(url: &str, tls: &ClientTls) -> Result<ServiceDocument> {
        let body = tacenta_transport::http_get(url, tls)
            .await
            .map_err(|e| Error::Discovery(format!("{}: {e}", shown(url))))?;
        serde_json::from_slice(&body)
            .map_err(|e| Error::Discovery(format!("{}: not a service document: {e}", shown(url))))
    }

    /// Build a handle from a document fetched from `url`, holding the
    /// document to what a document from that origin may say (see the module
    /// documentation). [`connect_via`](Self::connect_via) is a fetch followed
    /// by this.
    pub async fn from_discovered(
        api_key: &str,
        url: &str,
        doc: &ServiceDocument,
        tls: &ClientTls,
    ) -> Result<Tacenta> {
        check_against_origin(url, doc)?;
        Tacenta::from_document(api_key, doc, tls).await
    }

    /// Build a handle from a service document already in hand, exactly as it
    /// says. No origin check: the caller vouches for the document (it wrote
    /// it, or fetched it and checked it). Resolves each `host:port` once;
    /// `tls` is used when the document says web-PKI.
    pub async fn from_document(
        api_key: &str,
        doc: &ServiceDocument,
        tls: &ClientTls,
    ) -> Result<Tacenta> {
        if doc.version != tacenta_discovery::VERSION {
            return Err(Error::Discovery(format!(
                "service document version {} is not one this client reads",
                doc.version
            )));
        }
        let trust = match &doc.tls {
            // The caller's trust, which may be narrower than the web PKI.
            Tls::WebPki => Some((doc.server_name.clone(), tls.clone())),
            other => tacenta_transport::trust_for(other, &doc.server_name)
                .map_err(|e| Error::Discovery(format!("private trust anchors: {e}")))?,
        };
        let (directory, relay, accounts, provisioning) = tokio::try_join!(
            resolve(&doc.directory),
            resolve(&doc.relay),
            resolve(&doc.accounts),
            resolve(&doc.provisioning),
        )?;
        Ok(Tacenta {
            api_key: api_key.to_owned(),
            endpoints: Endpoints {
                directory,
                relay,
                accounts,
                provisioning,
            },
            trust,
            origin_tls: tls.clone(),
            carriage: match &doc.ws {
                Some(base) => Carriage::Offered(base.trim_end_matches('/').to_owned()),
                None => Carriage::Tcp,
            },
        })
    }

    /// Reach the services over the document's WebSocket carriage instead of
    /// their TCP ports: the path a browser or Node client takes, available to
    /// a native client too (to test it, or to cross a network that admits
    /// only HTTPS). Fails if the document offered no carriage.
    pub fn websocket(mut self) -> Result<Tacenta> {
        self.carriage = match self.carriage {
            Carriage::Offered(base) | Carriage::Active(base) => Carriage::Active(base),
            Carriage::Tcp | Carriage::Custom(_) => {
                return Err(Error::Discovery(
                    "the service document offers no websocket carriage".to_owned(),
                ));
            }
        };
        Ok(self)
    }

    /// Reach the services through streams `connector` opens, one per
    /// service, ignoring the document's addresses and carriage: the way a
    /// host that owns the sockets (a browser page, a test harness) lends
    /// them to the client.
    pub fn with_connector(mut self, connector: Arc<dyn Connector>) -> Tacenta {
        self.carriage = Carriage::Custom(connector);
        self
    }

    /// Whether the services are reached over the WebSocket carriage.
    pub fn is_websocket(&self) -> bool {
        matches!(self.carriage, Carriage::Active(_))
    }

    /// The WebSocket base URL the document offered, if any.
    pub fn websocket_url(&self) -> Option<&str> {
        match &self.carriage {
            Carriage::Offered(base) | Carriage::Active(base) => Some(base),
            Carriage::Tcp | Carriage::Custom(_) => None,
        }
    }

    /// Build a handle from known endpoints: no discovery. `trust` is `None`
    /// for a plaintext server, or the name the server's certificate presents
    /// with the trust to check it against (a pinned certificate, or
    /// [`ClientTls::web_pki`]).
    pub fn from_endpoints(
        api_key: &str,
        endpoints: Endpoints,
        trust: Option<(&str, &ClientTls)>,
    ) -> Tacenta {
        Tacenta {
            api_key: api_key.to_owned(),
            endpoints,
            trust: trust.map(|(name, tls)| (name.to_owned(), tls.clone())),
            origin_tls: ClientTls::web_pki(),
            carriage: Carriage::Tcp,
        }
    }

    /// The tenant API key this handle carries.
    pub fn api_key(&self) -> &str {
        &self.api_key
    }

    /// The name the server's certificate presents; `None` for a plaintext
    /// server.
    pub fn server_name(&self) -> Option<&str> {
        self.trust.as_ref().map(|(name, _)| name.as_str())
    }

    /// Where the four services are.
    pub fn endpoints(&self) -> &Endpoints {
        &self.endpoints
    }

    /// Whether connections are over TLS.
    pub fn is_tls(&self) -> bool {
        self.trust.is_some()
    }

    fn dialer(&self) -> Dialer {
        match &self.carriage {
            Carriage::Active(base) => Dialer::WebSocket {
                base: base.clone(),
                // The carriage terminates at the discovery origin, so a
                // wss:// socket is checked under the trust the document came
                // in under, not the services' own.
                tls: self.origin_tls.clone(),
            },
            Carriage::Custom(connector) => Dialer::Custom(connector.clone()),
            _ => Dialer::Tcp {
                trust: self.trust.clone(),
            },
        }
    }

    /// Create a user in this tenant.
    pub async fn sign_up(&self, username: &str, password: &str) -> Result<()> {
        DefaultClient::sign_up_trusting(
            self.endpoints.accounts,
            &self.dialer(),
            &self.api_key,
            username,
            password,
        )
        .await
    }

    /// Sign a user in on device `1` with a fresh device identity, returning a
    /// connected client. Persist [`Client::export_state`](crate::Client::export_state)
    /// and sign in again with [`sign_in_with_state`](Self::sign_in_with_state)
    /// on later runs.
    pub async fn sign_in(&self, username: &str, password: &str) -> Result<DefaultClient> {
        self.sign_in_device(username, password, 1).await
    }

    /// [`sign_in`](Self::sign_in) for a specific device number.
    pub async fn sign_in_device(
        &self,
        username: &str,
        password: &str,
        device: u8,
    ) -> Result<DefaultClient> {
        let config = self.account_config(username, password, device);
        DefaultClient::sign_in_trusting(&config, &self.dialer()).await
    }

    /// Sign in resuming persisted state (identity and live sessions) from
    /// [`Client::export_state`](crate::Client::export_state).
    pub async fn sign_in_with_state(
        &self,
        username: &str,
        password: &str,
        device: u8,
        state: &[u8],
    ) -> Result<DefaultClient> {
        let config = self.account_config(username, password, device);
        DefaultClient::sign_in_with_state_trusting(&config, &self.dialer(), state).await
    }

    /// Sign in resuming **sealed** state (from
    /// [`Client::export_state_sealed`](crate::Client::export_state_sealed))
    /// with `store` attached: the rollback-resistant path (decision 0078,
    /// anchor B). A forged state is refused, one older than the latest send
    /// is caught by the store's counter.
    pub async fn sign_in_with_state_sealed(
        &self,
        username: &str,
        password: &str,
        device: u8,
        state: &[u8],
        store: Arc<dyn SecureStore + Send + Sync>,
    ) -> Result<DefaultClient> {
        let config = self.account_config(username, password, device);
        DefaultClient::sign_in_with_state_sealed_trusting(&config, &self.dialer(), state, store)
            .await
    }

    fn account_config(&self, username: &str, password: &str, device: u8) -> AccountConfig {
        AccountConfig {
            directory: self.endpoints.directory,
            relay: self.endpoints.relay,
            accounts: self.endpoints.accounts,
            provisioning: self.endpoints.provisioning,
            api_key: self.api_key.clone(),
            identifier: username.to_owned(),
            password: password.to_owned(),
            device,
        }
    }
}

/// Hold a document to its origin (see the module documentation). Over
/// `https://`: no plaintext, and every name in it (the four hosts and
/// `server_name`) is the origin host or a subdomain of it. Over `http://`:
/// only from loopback, and then taken as is.
/// A URL or a host as an error message shows it: bounded and quoted, so a
/// document from a hostile origin cannot plant pages of text, or a line
/// that reads as something else, in what an app logs.
fn shown(s: &str) -> String {
    let mut t: String = s.chars().take(200).collect();
    if t.len() < s.len() {
        t.push('…');
    }
    format!("{t:?}")
}

fn check_against_origin(url: &str, doc: &ServiceDocument) -> Result<()> {
    let refuse = |m: String| Err(Error::Discovery(format!("{}: {m}", shown(url))));
    let Some(rest) = url.strip_prefix("https://") else {
        let authority = url
            .strip_prefix("http://")
            .and_then(|r| r.split('/').next())
            .unwrap_or("");
        if is_loopback(host_of(authority)) {
            return Ok(());
        }
        return refuse(
            "plaintext discovery is accepted from loopback only; use https, or build \
             the handle from a document you vouch for with Tacenta::from_document"
                .to_owned(),
        );
    };
    let authority = rest.split('/').next().unwrap_or("");
    let origin = host_of(authority);
    if doc.tls == Tls::None {
        return refuse(
            "the document offers plaintext services, but was fetched over https; \
             refusing the downgrade"
                .to_owned(),
        );
    }
    let names = doc
        .endpoints()
        .into_iter()
        .map(host_of)
        .chain(std::iter::once(doc.server_name.as_str()));
    for name in names {
        if !same_site(name, origin) {
            return refuse(format!(
                "the document names {name}, which is not {origin} or a subdomain of it"
            ));
        }
    }
    // The carriage is a fifth destination, held to the same rule, and it
    // must be wss: a ws:// URL would carry the credentials in plaintext,
    // the downgrade the tls check above refuses.
    if let Some(ws) = &doc.ws {
        let Some(rest) = ws.strip_prefix("wss://") else {
            return refuse(format!(
                "the document offers the carriage at {ws}; over https it must be wss://"
            ));
        };
        let ws_host = host_of(rest.split('/').next().unwrap_or(""));
        if !same_site(ws_host, origin) {
            return refuse(format!(
                "the document offers the carriage at {ws_host}, which is not {origin} or a subdomain of it"
            ));
        }
    }
    Ok(())
}

/// The machine itself: `localhost`, `127.0.0.0/8`, or `::1`.
fn is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// `name` is `origin` itself or a subdomain of it, case-insensitively.
fn same_site(name: &str, origin: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let origin = origin.trim_end_matches('.').to_ascii_lowercase();
    name == origin || name.ends_with(&format!(".{origin}"))
}

/// Resolve `host:port` to one socket address.
#[cfg(not(target_arch = "wasm32"))]
async fn resolve(hostport: &str) -> Result<SocketAddr> {
    let mut addrs = tokio::net::lookup_host(hostport)
        .await
        .map_err(|e| Error::Discovery(format!("cannot resolve {}: {e}", shown(hostport))))?;
    addrs
        .next()
        .ok_or_else(|| Error::Discovery(format!("no address for {}", shown(hostport))))
}

/// On wasm nothing dials an address (the browser opens the sockets), so a
/// name resolves to a placeholder carrying only the port.
#[cfg(target_arch = "wasm32")]
async fn resolve(hostport: &str) -> Result<SocketAddr> {
    if let Ok(addr) = hostport.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let port: u16 = hostport
        .rsplit(':')
        .next()
        .and_then(|p| p.parse().ok())
        .ok_or_else(|| Error::Discovery(format!("no port in {}", shown(hostport))))?;
    Ok(SocketAddr::from(([0, 0, 0, 0], port)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback() -> Endpoints {
        Endpoints {
            directory: "127.0.0.1:1".parse().unwrap(),
            relay: "127.0.0.1:2".parse().unwrap(),
            accounts: "127.0.0.1:3".parse().unwrap(),
            provisioning: "127.0.0.1:4".parse().unwrap(),
        }
    }

    #[test]
    fn debug_output_redacts_the_api_key() {
        let tls = ClientTls::web_pki();
        let t = Tacenta::from_endpoints(
            "tct_secret_value",
            loopback(),
            Some(("tacenta.example", &tls)),
        );
        let shown = format!("{t:?}");
        assert!(!shown.contains("tct_secret_value"), "{shown}");
        assert!(
            shown.contains("redacted") && shown.contains("tacenta.example"),
            "{shown}"
        );
        assert_eq!(t.server_name(), Some("tacenta.example"));
        let plain = Tacenta::from_endpoints("tct_x", loopback(), None);
        assert_eq!(plain.server_name(), None);
        assert!(!plain.is_tls());
    }

    #[tokio::test]
    async fn an_unknown_version_is_refused() {
        let mut doc = ServiceDocument::local("127.0.0.1");
        doc.version = 2;
        assert!(matches!(
            Tacenta::from_document("tct_x", &doc, &ClientTls::web_pki()).await,
            Err(Error::Discovery(_))
        ));
        doc.version = 1;
        let t = Tacenta::from_document("tct_x", &doc, &ClientTls::web_pki())
            .await
            .unwrap();
        assert!(!t.is_tls());
        assert_eq!(t.endpoints().accounts, "127.0.0.1:4722".parse().unwrap());
    }

    #[tokio::test]
    async fn bad_private_trust_anchors_are_a_discovery_error() {
        let doc = ServiceDocument::on(
            "127.0.0.1",
            "dev.example",
            [1, 2, 3, 4],
            Tls::PrivateCa {
                trust_anchors_pem: "not a certificate".into(),
            },
        );
        let err = Tacenta::from_document("tct_x", &doc, &ClientTls::web_pki())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, Error::Discovery(m) if m.contains("private trust anchors")),
            "{err}"
        );
    }

    #[test]
    fn an_https_document_may_not_turn_tls_off() {
        let url = "https://tacenta.example/.well-known/tacenta";
        let err =
            check_against_origin(url, &ServiceDocument::local("tacenta.example")).unwrap_err();
        assert!(err.to_string().contains("plaintext"), "{err}");
    }

    #[test]
    fn plaintext_discovery_is_loopback_only() {
        // The development server on this machine: taken as is.
        for url in [
            "http://127.0.0.1:4780/.well-known/tacenta",
            "http://localhost:4780/.well-known/tacenta",
            "http://[::1]:4780/.well-known/tacenta",
        ] {
            check_against_origin(url, &ServiceDocument::local("127.0.0.1")).unwrap();
            // Even a loopback document may name anything: it is the caller's machine.
            check_against_origin(url, &ServiceDocument::hosted("anything.example")).unwrap();
        }
        // A LAN gateway over http: one intercepted GET could redirect the
        // credentials, so it is refused with the way out named.
        let err = check_against_origin(
            "http://10.0.0.5:4780/.well-known/tacenta",
            &ServiceDocument::local("10.0.0.5"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("from_document"), "{err}");
        assert!(
            check_against_origin(
                "http://gateway.example/.well-known/tacenta",
                &ServiceDocument::local("gateway.example")
            )
            .is_err()
        );
    }

    #[test]
    fn an_https_document_may_not_name_another_domain() {
        let url = "https://tacenta.example/.well-known/tacenta";
        check_against_origin(url, &ServiceDocument::hosted("tacenta.example")).unwrap();
        check_against_origin(url, &ServiceDocument::hosted("Relay.Tacenta.Example")).unwrap();
        // A subdomain for the services, the apex for the certificate: allowed.
        let split = ServiceDocument::on(
            "svc.tacenta.example",
            "tacenta.example",
            [1, 2, 3, 4],
            Tls::WebPki,
        );
        check_against_origin(url, &split).unwrap();

        let err =
            check_against_origin(url, &ServiceDocument::hosted("attacker.example")).unwrap_err();
        assert!(err.to_string().contains("attacker.example"), "{err}");
        let err =
            check_against_origin(url, &ServiceDocument::hosted("nottacenta.example")).unwrap_err();
        assert!(err.to_string().contains("nottacenta.example"), "{err}");
        let mut name_only = ServiceDocument::hosted("tacenta.example");
        name_only.server_name = "attacker.example".into();
        assert!(check_against_origin(url, &name_only).is_err());
        // An IP origin admits only itself.
        check_against_origin(
            "https://[2001:db8::1]:4780/x",
            &ServiceDocument::on("2001:db8::1", "2001:db8::1", [1, 2, 3, 4], Tls::WebPki),
        )
        .unwrap();
        assert!(
            check_against_origin("https://10.0.0.1/x", &ServiceDocument::hosted("10.0.0.2"))
                .is_err()
        );
    }

    #[test]
    fn the_carriage_is_held_to_the_origin_and_must_be_wss() {
        let url = "https://tacenta.example/.well-known/tacenta";
        let hosted = || ServiceDocument::hosted("tacenta.example");
        check_against_origin(url, &hosted().with_ws("wss://tacenta.example/v1/ws")).unwrap();
        check_against_origin(url, &hosted().with_ws("wss://ws.tacenta.example/v1/ws")).unwrap();
        let err = check_against_origin(url, &hosted().with_ws("wss://attacker.example/v1/ws"))
            .unwrap_err();
        assert!(err.to_string().contains("attacker.example"), "{err}");
        let err = check_against_origin(url, &hosted().with_ws("ws://tacenta.example:4780/v1/ws"))
            .unwrap_err();
        assert!(err.to_string().contains("must be wss"), "{err}");
    }

    #[tokio::test]
    async fn the_carriage_is_offered_then_taken_and_its_slash_trimmed() {
        let doc: ServiceDocument = serde_json::from_str(
            r#"{"version":1,"server_name":"127.0.0.1","directory":"127.0.0.1:1","relay":"127.0.0.1:2","accounts":"127.0.0.1:3","provisioning":"127.0.0.1:4","tls":"none","ws":"ws://127.0.0.1:4780/v1/ws/"}"#,
        )
        .unwrap();
        let t = Tacenta::from_document("tct_x", &doc, &ClientTls::web_pki())
            .await
            .unwrap();
        assert!(!t.is_websocket());
        assert_eq!(t.websocket_url(), Some("ws://127.0.0.1:4780/v1/ws"));
        let t = t.websocket().unwrap();
        assert!(t.is_websocket());
        assert!(
            matches!(t.dialer(), Dialer::WebSocket { base, .. } if base == "ws://127.0.0.1:4780/v1/ws")
        );
        let plain = Tacenta::from_document(
            "tct_x",
            &ServiceDocument::local("127.0.0.1"),
            &ClientTls::web_pki(),
        )
        .await
        .unwrap();
        assert!(plain.websocket().is_err());
    }
}
