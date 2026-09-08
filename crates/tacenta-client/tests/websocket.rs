//! The whole handle through the WebSocket carriage (decision 0090):
//! a real server, the gateway in front of it, a document offering the
//! carriage, and two users who sign up, sign in, message and reconnect
//! without any of them touching a TCP port of the server.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use tacenta_accounts::{AccountResponse, AccountStore, Accounts};
use tacenta_client::{ClientTls, ServiceDocument, Tacenta, Tls};
use tacenta_gateway::{GatewayState, app};
use tacenta_server::{Config as ServerConfig, Server};
use tacenta_transport::AccountConnection;

async fn server() -> ([u16; 4], String) {
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
        registration_max_per_hour: None,
        registration_policy: None,
        max_connections: None,
    })
    .await
    .unwrap();
    let ports = [
        server.directory_addr().unwrap().port(),
        server.relay_addr().unwrap().port(),
        server.accounts_addr().unwrap().port(),
        server.provisioning_addr().unwrap().port(),
    ];
    let accounts = server.accounts_addr().unwrap();
    tokio::spawn(server.serve());
    let mut admin = AccountConnection::connect(accounts).await.unwrap();
    let AccountResponse::TenantCreated { api_key, .. } = admin
        .sign_up_tenant("acme", "admin@acme.example", "correct horse")
        .await
        .unwrap()
    else {
        panic!("expected a tenant");
    };
    (ports, api_key)
}

/// The gateway serving a document that offers the carriage at itself.
async fn gateway(ports: [u16; 4]) -> ServiceDocument {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let doc = ServiceDocument::on("127.0.0.1", "127.0.0.1", ports, Tls::None)
        .with_ws(&format!("ws://127.0.0.1:{port}/v1/ws"));
    let state =
        GatewayState::with_service(Arc::new(AccountStore::memory(Accounts::new())), doc.clone())
            .unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app(state, &[])).await.unwrap();
    });
    doc
}

#[tokio::test]
async fn two_users_message_through_the_carriage() {
    let (ports, api_key) = server().await;
    let doc = gateway(ports).await;
    let tenant = Tacenta::from_document(&api_key, &doc, &ClientTls::web_pki())
        .await
        .unwrap()
        .websocket()
        .unwrap();
    assert!(tenant.is_websocket());

    tenant.sign_up("alice", "hunter2!!").await.unwrap();
    tenant.sign_up("bob", "hunter2!!").await.unwrap();
    let mut alice = tenant.sign_in("alice", "hunter2!!").await.unwrap();
    let mut bob = tenant.sign_in("bob", "hunter2!!").await.unwrap();

    let to_bob = alice.find("bob").await.unwrap().unwrap();
    alice.send(&to_bob.address, b"over the wire").await.unwrap();
    let inbox = bob.receive().await.unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].plaintext, b"over the wire");

    // The relay's push and the reply come back the same way.
    bob.send(alice.address(), b"and back").await.unwrap();
    assert_eq!(alice.receive().await.unwrap()[0].plaintext, b"and back");

    // A reconnect re-dials directory and relay through the carriage too.
    alice.reconnect().await.unwrap();
    bob.send(alice.address(), b"after reconnect").await.unwrap();
    assert_eq!(
        alice.receive().await.unwrap()[0].plaintext,
        b"after reconnect"
    );
}
