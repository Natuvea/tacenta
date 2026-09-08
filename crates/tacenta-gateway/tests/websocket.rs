//! The WebSocket carriage end to end (decision 0090): a real
//! `tacenta-server`, the gateway in front of it, and a client that reaches
//! the services only through `ws://{gateway}/v1/ws/{service}`.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use tacenta_accounts::{AccountResponse, AccountStore, Accounts};
use tacenta_discovery::{ServiceDocument, Tls};
use tacenta_gateway::{GatewayState, app};
use tacenta_server::{Config as ServerConfig, Server};
use tacenta_transport::{AccountConnection, ClientTls, DirConnection};

/// A plaintext server on loopback, and the document describing it.
async fn server() -> ServiceDocument {
    let server = Server::bind(&ServerConfig {
        bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
        directory_port: 0,
        relay_port: 0,
        accounts_port: 0,
        provisioning_port: 0,
        database_url: None,
        data_dir: None,
        tls: None,
        snapshot_interval: None,
        relay_max_total_bytes: None,
        registration_policy: None,
        max_connections: None,
        registration_max_per_hour: None,
    })
    .await
    .unwrap();
    let ports = [
        server.directory_addr().unwrap().port(),
        server.relay_addr().unwrap().port(),
        server.accounts_addr().unwrap().port(),
        server.provisioning_addr().unwrap().port(),
    ];
    tokio::spawn(server.serve());
    ServiceDocument::on("127.0.0.1", "127.0.0.1", ports, Tls::None)
}

/// The gateway over `doc`, serving; returns its `host:port`. Its own account
/// store is separate from the server's: the carriage pipes bytes to the
/// server's account service, which is the one the test signs up against.
async fn gateway(doc: ServiceDocument) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let store = Arc::new(AccountStore::memory(Accounts::new()));
    // The document offers the carriage at this gateway; without the offer
    // the paths answer 404.
    let doc = doc.with_ws(&format!("ws://127.0.0.1:{}/v1/ws", addr.port()));
    let state = GatewayState::with_service(store, doc).unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app(state, &[])).await.unwrap();
    });
    format!("127.0.0.1:{}", addr.port())
}

#[tokio::test]
async fn the_services_are_reachable_over_the_websocket() {
    let gw = gateway(server().await).await;
    let tls = ClientTls::web_pki();

    let mut admin = AccountConnection::connect_ws(&format!("ws://{gw}/v1/ws/accounts"), &tls)
        .await
        .unwrap();
    let AccountResponse::TenantCreated { api_key, .. } = admin
        .sign_up_tenant("acme", "admin@acme.example", "correct horse")
        .await
        .unwrap()
    else {
        panic!("expected a tenant");
    };
    let mut user = AccountConnection::connect_ws(&format!("ws://{gw}/v1/ws/accounts"), &tls)
        .await
        .unwrap();
    assert!(matches!(
        user.sign_up_user(&api_key, "alice", "hunter2!!")
            .await
            .unwrap(),
        AccountResponse::UserCreated { .. }
    ));
    assert!(matches!(
        user.sign_in(&api_key, "alice", "hunter2!!").await.unwrap(),
        AccountResponse::SignedIn { .. }
    ));

    // The directory answers a lookup through the same carriage.
    let mut dir = DirConnection::connect_ws(&format!("ws://{gw}/v1/ws/directory"), &tls)
        .await
        .unwrap();
    let nobody = tacenta_relay::DeviceAddr::new("acme/nobody", 1);
    // Whatever the directory says about a stranger, it said it through the
    // carriage: the round trip is the assertion.
    let _answer = dir.lookup(&nobody).await.unwrap();
}

#[tokio::test]
async fn without_an_offered_carriage_the_paths_are_closed() {
    let doc = server().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state =
        GatewayState::with_service(Arc::new(AccountStore::memory(Accounts::new())), doc).unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app(state, &[])).await.unwrap();
    });
    let err = AccountConnection::connect_ws(
        &format!("ws://{addr}/v1/ws/accounts"),
        &ClientTls::web_pki(),
    )
    .await
    .map(|_| ())
    .unwrap_err();
    assert!(err.to_string().contains("404"), "{err}");
}

#[tokio::test]
async fn a_service_that_is_down_is_a_bad_gateway() {
    // A document naming ports nothing listens on: the dial fails before the
    // upgrade, so the client reads a 502 rather than a socket that closes.
    let doc = ServiceDocument::on("127.0.0.1", "127.0.0.1", [1, 1, 1, 1], Tls::None);
    let gw = gateway(doc).await;
    let err =
        AccountConnection::connect_ws(&format!("ws://{gw}/v1/ws/accounts"), &ClientTls::web_pki())
            .await
            .map(|_| ())
            .unwrap_err();
    assert!(err.to_string().contains("502"), "{err}");
}

#[tokio::test]
async fn an_unknown_service_path_does_not_upgrade() {
    let gw = gateway(server().await).await;
    let err =
        AccountConnection::connect_ws(&format!("ws://{gw}/v1/ws/mailbox"), &ClientTls::web_pki())
            .await
            .map(|_| ())
            .unwrap_err();
    assert!(err.to_string().contains("404"), "{err}");
}
