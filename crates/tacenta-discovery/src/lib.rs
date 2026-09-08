//! The service document (decision 0090).
//!
//! A Tacenta server publishes one small JSON document at
//! [`WELL_KNOWN_PATH`] saying where its four framed services are and how a
//! client should trust them. The tenant handle in `tacenta-client` fetches it
//! once and derives every endpoint from it, so no sample and no app carries
//! four host and port pairs; a deployment that moves a service moves it here.
//!
//! This crate is the definition both sides share: `tacenta-gateway` serialises
//! it, `tacenta-client` deserialises it, and a change to the shape is a change
//! to one type that both compile against.
//!
//! The wire form, version 1:
//!
//! ```json
//! {
//!   "version": 1,
//!   "server_name": "tacenta.example",
//!   "directory": "tacenta.example:4720",
//!   "relay": "tacenta.example:4721",
//!   "accounts": "tacenta.example:4722",
//!   "provisioning": "tacenta.example:4723",
//!   "tls": "web-pki",
//!   "ws": "wss://tacenta.example/v1/ws"
//! }
//! ```
//!
//! `ws`, when present, is the base URL of the WebSocket carriage of the same
//! four services: `{ws}/directory`, `{ws}/relay`, `{ws}/accounts`,
//! `{ws}/provisioning`, each carrying that service's framing as binary
//! messages (decision 0090). A browser or Node client, which cannot
//! open a TCP socket, uses these; a native client may.
//!
//! `tls` is `"web-pki"`, `"none"`, or `{"private-ca": {"trust_anchors_pem":
//! "..."}}` (see [`Tls`]). Fields may be added within version 1; a reader ignores
//! fields it does not know. The version number changes only when an existing
//! field changes meaning.

use serde::{Deserialize, Serialize};

/// Where a server publishes its document.
pub const WELL_KNOWN_PATH: &str = "/.well-known/tacenta";

/// The document format this crate writes and reads.
pub const VERSION: u32 = 1;

/// The server's default ports for directory, relay, accounts, provisioning.
pub const DEFAULT_PORTS: [u16; 4] = [4720, 4721, 4722, 4723];

/// How a client trusts the server behind the four services.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Tls {
    /// No TLS: a development server on loopback. A client refuses this from a
    /// document it fetched over `https://`.
    None,
    /// A publicly trusted certificate presenting `server_name`: the hosted
    /// deployment, and any self-hosted one with a public certificate.
    WebPki,
    /// A private trust root, for a self-hosted deployment whose services
    /// present a certificate the public web PKI does not know. The PEM holds
    /// the trust anchors: the private CA's certificate, or the server's own
    /// certificate when it is self-signed. A leaf issued by a CA does not
    /// verify on its own; the CA is what goes here. The document is fetched
    /// over web-PKI `https://`, so the anchors arrive authenticated, and the
    /// certificate the services present must still name `server_name`.
    PrivateCa { trust_anchors_pem: String },
}

/// The wire name of the mode, for logs: `none`, `web-pki`, `private-ca`.
impl std::fmt::Display for Tls {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Tls::None => "none",
            Tls::WebPki => "web-pki",
            Tls::PrivateCa { .. } => "private-ca",
        })
    }
}

/// The document itself. The four services are `host:port` strings, resolved
/// by the reader; `server_name` is the name the TLS certificate presents,
/// which is the host in every deployment so far but is carried separately so
/// that it need not be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceDocument {
    /// The document's own format version; see [`VERSION`].
    pub version: u32,
    /// The name the server's TLS certificate presents.
    pub server_name: String,
    /// The directory service, as `host:port`.
    pub directory: String,
    /// The relay, as `host:port`.
    pub relay: String,
    /// The account service, as `host:port`.
    pub accounts: String,
    /// The provisioning service, as `host:port`.
    pub provisioning: String,
    /// How to trust the server.
    pub tls: Tls,
    /// The WebSocket base URL, if the deployment offers one; see the module
    /// documentation. Absent from documents written before it existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ws: Option<String>,
}

impl ServiceDocument {
    /// The four services on `host`, on the default ports, over web-PKI TLS
    /// presenting `host`: a hosted deployment.
    pub fn hosted(host: &str) -> ServiceDocument {
        ServiceDocument::on(host, host, DEFAULT_PORTS, Tls::WebPki)
    }

    /// The four services on `host`, on the default ports, without TLS: a
    /// development server on loopback.
    pub fn local(host: &str) -> ServiceDocument {
        ServiceDocument::on(host, host, DEFAULT_PORTS, Tls::None)
    }

    /// The four services on `host` at `ports` (directory, relay, accounts,
    /// provisioning), trusted as `tls` under `server_name`.
    pub fn on(host: &str, server_name: &str, ports: [u16; 4], tls: Tls) -> ServiceDocument {
        let host = if host.contains(':') && !host.starts_with('[') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        ServiceDocument {
            version: VERSION,
            server_name: server_name.to_owned(),
            directory: format!("{host}:{}", ports[0]),
            relay: format!("{host}:{}", ports[1]),
            accounts: format!("{host}:{}", ports[2]),
            provisioning: format!("{host}:{}", ports[3]),
            tls,
            ws: None,
        }
    }

    /// The same document, offering the WebSocket carriage at `ws` (a base
    /// URL such as `wss://tacenta.com/v1/ws`, without a trailing slash).
    pub fn with_ws(mut self, ws: &str) -> ServiceDocument {
        self.ws = Some(ws.trim_end_matches('/').to_owned());
        self
    }

    /// The WebSocket URL for one service (`directory`, `relay`, `accounts`,
    /// `provisioning`), if the document offers the carriage.
    pub fn ws_url(&self, service: &str) -> Option<String> {
        self.ws.as_ref().map(|base| format!("{base}/{service}"))
    }

    /// The four `host:port` entries, in the order directory, relay, accounts,
    /// provisioning.
    pub fn endpoints(&self) -> [&str; 4] {
        [
            &self.directory,
            &self.relay,
            &self.accounts,
            &self.provisioning,
        ]
    }
}

/// The host part of a `host:port` entry, without IPv6 brackets.
pub fn host_of(hostport: &str) -> &str {
    if let Some(rest) = hostport.strip_prefix('[') {
        return rest.split(']').next().unwrap_or("");
    }
    hostport.rsplit_once(':').map_or(hostport, |(h, _)| h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hosted_document_serialises_to_the_documented_form() {
        let json = serde_json::to_string(&ServiceDocument::hosted("tacenta.com")).unwrap();
        assert_eq!(
            json,
            r#"{"version":1,"server_name":"tacenta.com","directory":"tacenta.com:4720","relay":"tacenta.com:4721","accounts":"tacenta.com:4722","provisioning":"tacenta.com:4723","tls":"web-pki"}"#
        );
        let back: ServiceDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ServiceDocument::hosted("tacenta.com"));

        let with_ws = ServiceDocument::hosted("tacenta.com").with_ws("wss://tacenta.com/v1/ws/");
        let json = serde_json::to_string(&with_ws).unwrap();
        assert!(
            json.ends_with(r#""tls":"web-pki","ws":"wss://tacenta.com/v1/ws"}"#),
            "{json}"
        );
        assert_eq!(
            with_ws.ws_url("relay").as_deref(),
            Some("wss://tacenta.com/v1/ws/relay")
        );
        assert_eq!(ServiceDocument::hosted("x").ws_url("relay"), None);
    }

    #[test]
    fn the_trust_modes_have_stable_wire_names() {
        assert_eq!(serde_json::to_string(&Tls::None).unwrap(), r#""none""#);
        assert_eq!(serde_json::to_string(&Tls::WebPki).unwrap(), r#""web-pki""#);
        let private = Tls::PrivateCa {
            trust_anchors_pem: "-----BEGIN CERTIFICATE-----\n".into(),
        };
        let json = serde_json::to_string(&private).unwrap();
        assert!(
            json.starts_with(r#"{"private-ca":{"trust_anchors_pem":"#),
            "{json}"
        );
        assert_eq!(serde_json::from_str::<Tls>(&json).unwrap(), private);
        assert!(serde_json::from_str::<Tls>(r#""off""#).is_err());
        assert_eq!(private.to_string(), "private-ca");
        assert_eq!(Tls::WebPki.to_string(), "web-pki");
    }

    #[test]
    fn unknown_fields_are_ignored_within_a_version() {
        let doc: ServiceDocument = serde_json::from_str(
            r#"{"version":1,"server_name":"x","directory":"x:1","relay":"x:2","accounts":"x:3","provisioning":"x:4","tls":"none","ws":"wss://x/ws"}"#,
        )
        .unwrap();
        assert_eq!(doc.tls, Tls::None);
    }

    #[test]
    fn hosts_are_read_back_from_entries() {
        assert_eq!(host_of("tacenta.com:4720"), "tacenta.com");
        assert_eq!(host_of("[::1]:4720"), "::1");
        assert_eq!(host_of("127.0.0.1:4720"), "127.0.0.1");
        let doc = ServiceDocument::on("::1", "::1", [1, 2, 3, 4], Tls::None);
        assert_eq!(doc.relay, "[::1]:2");
        assert_eq!(host_of(&doc.relay), "::1");
    }
}
