//! `ClientTls` on wasm: a name for a trust the browser holds. In the
//! browser the byte stream comes from a `wss://` WebSocket whose
//! certificate the browser checked against its own roots, so there is no
//! TLS to do here; the type exists so the client crate's handle, which
//! carries a trust alongside every endpoint, compiles unchanged.

/// The browser's trust: nothing to configure, nothing to wrap.
#[derive(Clone, Debug, Default)]
pub struct ClientTls {}

impl ClientTls {
    /// The public web PKI, as the browser applies it.
    pub fn web_pki() -> ClientTls {
        ClientTls {}
    }

    /// A private trust root cannot be installed from a page; a browser
    /// trusts what its own store trusts. The value is the browser's trust.
    pub fn trusting_pem(_pem: &[u8]) -> std::io::Result<ClientTls> {
        Ok(ClientTls {})
    }
}

/// The client trust a service document's `tls` mode calls for, on wasm. A
/// browser never dials the services' TLS ports itself: it reaches them
/// through the `wss://` carriage, whose certificate it checked against its
/// own roots. So the services' trust mode is recorded, not acted on, and a
/// private root the deployment names is the browser's business (an
/// enterprise root in the OS store) rather than a reason to refuse.
pub fn trust_for(
    tls: &tacenta_discovery::Tls,
    server_name: &str,
) -> std::io::Result<Option<(String, ClientTls)>> {
    use tacenta_discovery::Tls;
    Ok(match tls {
        Tls::None => None,
        Tls::WebPki | Tls::PrivateCa { .. } => Some((server_name.to_owned(), ClientTls::web_pki())),
    })
}
