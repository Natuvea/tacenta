//! The gateway binary — an env-configured entrypoint over the library.
//!
//! Environment:
//! - `GATEWAY_BIND` — listen address (default `0.0.0.0:4780`).
//! - `GATEWAY_ALLOWED_ORIGINS` — comma-separated CORS origins (e.g.
//!   `https://tacenta.com`). Empty = no browser origin allowed (API still
//!   answers non-browser clients).
//! - `DATABASE_URL` — with the `postgres` feature, run on the shared durable
//!   store; otherwise (or without the feature) an in-memory store is used, which
//!   is process-local and for development only.
//! - `GATEWAY_SERVICE_HOST` — the host the service document names for the four
//!   TCP services. Unset means a development gateway publishing loopback
//!   without TLS. `GATEWAY_SERVICE_TLS` — `web-pki` (the default once a host
//!   is named), `none`, or `private-ca` with `GATEWAY_SERVICE_CERT` naming a
//!   PEM file of trust anchors; any other value refuses to start. The ports
//!   follow `TACENTA_*_PORT`, the server's own names. The document is what a
//!   client fetches at `/.well-known/tacenta` to learn where to connect
//!   (decision 0090). The gateway asserts the server's TLS mode; it
//!   cannot see it, so the two must be configured together.
//! - `GATEWAY_SERVICE_WS` — the WebSocket base URL the document offers:
//!   derived as `wss://{host}/v1/ws` for a named host with TLS and as
//!   `ws://127.0.0.1:{bind port}/v1/ws` for the loopback development
//!   gateway, otherwise named here; `none` withholds the carriage, and the
//!   paths then answer 404.
//! - `GATEWAY_UPSTREAM_HOST` — where the gateway itself dials the four
//!   services for that carriage, when the document's public host is not
//!   the way to reach them from here (an internal name).
//!
//! Terminate TLS at a front proxy that also sets `X-Forwarded-For`; the request
//! body carries a plaintext password.

use std::sync::Arc;

use tacenta_accounts::{AccountStore, Accounts};
use tacenta_gateway::{GatewayState, ServiceDocument, Tls, app};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = std::env::var("GATEWAY_BIND").unwrap_or_else(|_| "0.0.0.0:4780".to_owned());
    let origins: Vec<String> = std::env::var("GATEWAY_ALLOWED_ORIGINS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect();

    let service = service_document(|name| std::env::var(name).ok())?;

    let store = build_store().await?;
    let upstream_host = std::env::var("GATEWAY_UPSTREAM_HOST")
        .ok()
        .filter(|h| !h.trim().is_empty());
    let state =
        GatewayState::with_upstream(Arc::new(store), service.clone(), upstream_host.as_deref())?;
    let router = app(state, &origins);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    eprintln!("tacenta-gateway: listening on {bind}, CORS origins: {origins:?}");
    eprintln!(
        "tacenta-gateway: service document names {} at {} (tls: {}); websocket carriage {}; dialling services at {}",
        service.server_name,
        service.accounts,
        service.tls,
        service.ws.as_deref().unwrap_or("not offered"),
        upstream_host.as_deref().unwrap_or("the document's hosts")
    );
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

/// The document this deployment publishes, from the environment, with no
/// silent default that names some other server:
///
/// - `GATEWAY_SERVICE_HOST` — the host the four services are on. Unset means
///   a development gateway on loopback, publishing `127.0.0.1` without TLS.
/// - `GATEWAY_SERVICE_TLS` — `web-pki` (the default once a host is named),
///   `none`, or `private-ca` with the trust anchors read from the PEM file
///   `GATEWAY_SERVICE_CERT` names. Anything else is a refusal, not a guess: a
///   typo here would send every client's credentials the wrong way.
/// - `TACENTA_DIRECTORY_PORT`, `TACENTA_RELAY_PORT`, `TACENTA_ACCOUNTS_PORT`,
///   `TACENTA_PROVISIONING_PORT` — the ports, by the same names the server
///   reads them under, so a deployment that moves one sets it once.
fn service_document(env: impl Fn(&str) -> Option<String>) -> Result<ServiceDocument, String> {
    let host = env("GATEWAY_SERVICE_HOST")
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty());
    let tls = match env("GATEWAY_SERVICE_TLS").as_deref() {
        Some("web-pki") => Tls::WebPki,
        Some("none") => Tls::None,
        Some("private-ca") => {
            let path = env("GATEWAY_SERVICE_CERT").ok_or(
                "GATEWAY_SERVICE_TLS is private-ca; GATEWAY_SERVICE_CERT must name the PEM",
            )?;
            let pem = std::fs::read_to_string(&path)
                .map_err(|e| format!("GATEWAY_SERVICE_CERT {path}: {e}"))?;
            if !pem.contains("-----BEGIN CERTIFICATE-----") {
                return Err(format!(
                    "GATEWAY_SERVICE_CERT {path}: no certificate in the PEM"
                ));
            }
            Tls::PrivateCa {
                trust_anchors_pem: pem,
            }
        }
        None if host.is_some() => Tls::WebPki,
        None => Tls::None,
        Some(other) => {
            return Err(format!(
                "GATEWAY_SERVICE_TLS is {other:?}; it must be `web-pki` or `none`"
            ));
        }
    };
    let named = host.is_some();
    let host = host.unwrap_or_else(|| "127.0.0.1".to_owned());
    if tls != Tls::None && host.parse::<std::net::IpAddr>().is_ok() {
        return Err(format!(
            "GATEWAY_SERVICE_HOST is the address {host}; {tls} trust needs the name on the certificate"
        ));
    }
    let mut ports = tacenta_discovery::DEFAULT_PORTS;
    for (slot, name) in ports.iter_mut().zip([
        "TACENTA_DIRECTORY_PORT",
        "TACENTA_RELAY_PORT",
        "TACENTA_ACCOUNTS_PORT",
        "TACENTA_PROVISIONING_PORT",
    ]) {
        if let Some(v) = env(name) {
            *slot = v
                .trim()
                .parse()
                .map_err(|_| format!("{name} is {v:?}; it must be a port number"))?;
        }
    }
    let doc = ServiceDocument::on(&host, &host, ports, tls.clone());
    // The carriage URL: named explicitly, or derived where the derivation is
    // safe. A named host with TLS sits behind a 443 proxy (wss://host/v1/ws);
    // the loopback development gateway is reached on its own listen port.
    // A named host without TLS is reached on some port only the operator
    // knows, so nothing is derived and the document offers no carriage
    // unless GATEWAY_SERVICE_WS names one.
    let ws = match env("GATEWAY_SERVICE_WS").as_deref().map(str::trim) {
        Some("none") => None,
        Some(url) if !url.is_empty() => Some(url.to_owned()),
        _ if tls != Tls::None => Some(format!("wss://{host}/v1/ws")),
        _ if named => None,
        _ => {
            let bind = env("GATEWAY_BIND").unwrap_or_else(|| "0.0.0.0:4780".to_owned());
            let port = bind.rsplit(':').next().unwrap_or("4780");
            Some(format!("ws://127.0.0.1:{port}/v1/ws"))
        }
    };
    Ok(match ws {
        Some(ws) => doc.with_ws(&ws),
        None => doc,
    })
}

#[cfg(feature = "postgres")]
async fn build_store() -> Result<AccountStore, Box<dyn std::error::Error>> {
    if let Ok(url) = std::env::var("DATABASE_URL") {
        let pg = tacenta_accounts::pg::PgAccounts::connect(&url).await?;
        pg.migrate().await?;
        eprintln!("tacenta-gateway: using the PostgreSQL account store");
        return Ok(AccountStore::postgres(pg));
    }
    eprintln!("tacenta-gateway: DATABASE_URL unset — using the in-memory store (development only)");
    Ok(AccountStore::memory(Accounts::new()))
}

#[cfg(not(feature = "postgres"))]
async fn build_store() -> Result<AccountStore, Box<dyn std::error::Error>> {
    eprintln!(
        "tacenta-gateway: built without the postgres feature — using the in-memory store (development only)"
    );
    Ok(AccountStore::memory(Accounts::new()))
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    eprintln!("tacenta-gateway: shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(vars: &[(&str, &str)]) -> Result<ServiceDocument, String> {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        service_document(|name| vars.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone()))
    }

    #[test]
    fn no_environment_is_a_loopback_development_document() {
        assert_eq!(
            with(&[]).unwrap(),
            ServiceDocument::local("127.0.0.1").with_ws("ws://127.0.0.1:4780/v1/ws")
        );
        let doc = with(&[("GATEWAY_BIND", "127.0.0.1:9000")]).unwrap();
        assert_eq!(doc.ws.as_deref(), Some("ws://127.0.0.1:9000/v1/ws"));
    }

    #[test]
    fn a_named_host_is_web_pki_unless_told_otherwise() {
        let doc = with(&[("GATEWAY_SERVICE_HOST", "chat.example.org")]).unwrap();
        assert_eq!(
            doc,
            ServiceDocument::hosted("chat.example.org").with_ws("wss://chat.example.org/v1/ws")
        );
        let doc = with(&[
            ("GATEWAY_SERVICE_HOST", "10.0.0.5"),
            ("GATEWAY_SERVICE_TLS", "none"),
        ])
        .unwrap();
        assert_eq!(doc.tls, Tls::None);
        assert_eq!(doc.accounts, "10.0.0.5:4722");
        // A named plaintext host: the gateway cannot know its public port,
        // so no carriage is derived.
        assert_eq!(doc.ws, None);
    }

    #[test]
    fn the_websocket_carriage_can_be_named_or_withheld() {
        let doc = with(&[
            ("GATEWAY_SERVICE_HOST", "chat.example.org"),
            ("GATEWAY_SERVICE_WS", "wss://ws.chat.example.org/v1/ws/"),
        ])
        .unwrap();
        assert_eq!(doc.ws.as_deref(), Some("wss://ws.chat.example.org/v1/ws"));
        let doc = with(&[
            ("GATEWAY_SERVICE_HOST", "chat.example.org"),
            ("GATEWAY_SERVICE_WS", "none"),
        ])
        .unwrap();
        assert_eq!(doc.ws, None);
    }

    #[test]
    fn a_private_ca_is_read_from_its_pem_file() {
        let dir = std::env::temp_dir().join(format!("tacenta-gateway-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pem = dir.join("ca.pem");
        std::fs::write(
            &pem,
            "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        let doc = with(&[
            ("GATEWAY_SERVICE_HOST", "chat.example"),
            ("GATEWAY_SERVICE_TLS", "private-ca"),
            ("GATEWAY_SERVICE_CERT", pem.to_str().unwrap()),
        ])
        .unwrap();
        assert!(
            matches!(doc.tls, Tls::PrivateCa { ref trust_anchors_pem } if trust_anchors_pem.contains("AAAA"))
        );
        assert_eq!(doc.to_owned().tls.to_string(), "private-ca");
        let err = with(&[
            ("GATEWAY_SERVICE_HOST", "chat.example"),
            ("GATEWAY_SERVICE_TLS", "private-ca"),
        ])
        .unwrap_err();
        assert!(err.contains("GATEWAY_SERVICE_CERT"), "{err}");
        std::fs::write(&pem, "not a certificate").unwrap();
        let err = with(&[
            ("GATEWAY_SERVICE_HOST", "chat.example"),
            ("GATEWAY_SERVICE_TLS", "private-ca"),
            ("GATEWAY_SERVICE_CERT", pem.to_str().unwrap()),
        ])
        .unwrap_err();
        assert!(err.contains("no certificate"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_typo_in_the_tls_mode_is_refused_not_guessed() {
        for bad in ["off", "NONE", "false", "web_pki", ""] {
            let err = with(&[
                ("GATEWAY_SERVICE_HOST", "chat.example.org"),
                ("GATEWAY_SERVICE_TLS", bad),
            ])
            .unwrap_err();
            assert!(err.contains("GATEWAY_SERVICE_TLS"), "{bad:?}: {err}");
        }
    }

    #[test]
    fn web_pki_needs_a_name_not_an_address() {
        let err = with(&[("GATEWAY_SERVICE_HOST", "203.0.113.7")]).unwrap_err();
        assert!(err.contains("certificate"), "{err}");
    }

    #[test]
    fn the_ports_follow_the_servers_own_settings() {
        let doc = with(&[
            ("GATEWAY_SERVICE_HOST", "chat.example.org"),
            ("TACENTA_RELAY_PORT", "5721"),
        ])
        .unwrap();
        assert_eq!(doc.relay, "chat.example.org:5721");
        assert_eq!(doc.accounts, "chat.example.org:4722");
        let err = with(&[("TACENTA_RELAY_PORT", "lots")]).unwrap_err();
        assert!(err.contains("TACENTA_RELAY_PORT"), "{err}");
    }
}
