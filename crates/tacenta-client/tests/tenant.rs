//! The tenant handle end to end (decision 0090): a server publishes
//! its service document, a `Tacenta` handle discovers the endpoints from it,
//! and two users signed in through the handle message each other. No host or
//! port appears below the document.

use std::net::{IpAddr, Ipv4Addr};

use tacenta_accounts::AccountResponse;
use tacenta_client::{ClientTls, Endpoints, Tacenta};
use tacenta_server::{Config as ServerConfig, Server};
use tacenta_transport::AccountConnection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn server() -> (Endpoints, String) {
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
    let endpoints = Endpoints {
        directory: server.directory_addr().unwrap(),
        relay: server.relay_addr().unwrap(),
        accounts: server.accounts_addr().unwrap(),
        provisioning: server.provisioning_addr().unwrap(),
    };
    tokio::spawn(server.serve());

    let mut admin = AccountConnection::connect(endpoints.accounts)
        .await
        .unwrap();
    let AccountResponse::TenantCreated { api_key, .. } = admin
        .sign_up_tenant("acme", "admin@acme.example", "correct horse")
        .await
        .unwrap()
    else {
        panic!("expected a tenant");
    };
    (endpoints, api_key)
}

/// A one-request HTTP server that publishes `doc` as the service document.
async fn publish(doc: String) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 2048];
        let n = socket.read(&mut buf).await.unwrap();
        let request = String::from_utf8_lossy(&buf[..n]);
        assert!(
            request.starts_with("GET /.well-known/tacenta HTTP/1.1\r\n"),
            "{request}"
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            doc.len(),
            doc
        );
        socket.write_all(response.as_bytes()).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    format!("http://{addr}/.well-known/tacenta")
}

#[tokio::test]
async fn a_handle_discovers_the_endpoints_and_signs_users_in() {
    let (endpoints, api_key) = server().await;
    let doc = format!(
        r#"{{"version":1,"server_name":"127.0.0.1","directory":"{}","relay":"{}","accounts":"{}","provisioning":"{}","tls":"none"}}"#,
        endpoints.directory, endpoints.relay, endpoints.accounts, endpoints.provisioning
    );
    let url = publish(doc).await;

    let tenant = Tacenta::connect_via(&api_key, &url, &ClientTls::web_pki())
        .await
        .unwrap();
    assert_eq!(tenant.endpoints(), &endpoints);
    assert!(!tenant.is_tls());
    assert_eq!(tenant.server_name(), None);
    assert_eq!(tenant.api_key(), api_key);

    tenant.sign_up("alice", "hunter2!!").await.unwrap();
    tenant.sign_up("bob", "hunter2!!").await.unwrap();
    let mut alice = tenant.sign_in("alice", "hunter2!!").await.unwrap();
    let mut bob = tenant.sign_in("bob", "hunter2!!").await.unwrap();
    assert_eq!(alice.address().user, "acme/alice");

    let to_bob = alice.find("bob").await.unwrap().unwrap();
    alice.send(&to_bob.address, b"north dock").await.unwrap();
    let inbox = bob.receive().await.unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].plaintext, b"north dock");
    assert_eq!(inbox[0].from, *alice.address());
}

#[tokio::test]
async fn a_handle_resumes_persisted_state() {
    let (endpoints, api_key) = server().await;
    let tenant = Tacenta::from_endpoints(&api_key, endpoints, None);
    tenant.sign_up("carol", "hunter2!!").await.unwrap();
    tenant.sign_up("dave", "hunter2!!").await.unwrap();
    let mut carol = tenant.sign_in("carol", "hunter2!!").await.unwrap();
    let mut dave = tenant.sign_in("dave", "hunter2!!").await.unwrap();

    let to_dave = carol.find("dave").await.unwrap().unwrap();
    carol.send(&to_dave.address, b"first").await.unwrap();
    assert_eq!(dave.receive().await.unwrap()[0].plaintext, b"first");

    // Carol goes away and comes back through the handle with her state; the
    // session she had with Dave still decrypts.
    let state = carol.export_state().await.unwrap();
    drop(carol);
    let mut carol = tenant
        .sign_in_with_state("carol", "hunter2!!", 1, &state)
        .await
        .unwrap();
    dave.send(carol.address(), b"welcome back").await.unwrap();
    assert_eq!(carol.receive().await.unwrap()[0].plaintext, b"welcome back");
}

#[tokio::test]
async fn a_server_without_a_document_is_a_discovery_error() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 512];
        let _ = socket.read(&mut buf).await;
        socket
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });
    let err = Tacenta::connect_via(
        "tct_x",
        &format!("http://{addr}/.well-known/tacenta"),
        &ClientTls::web_pki(),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, tacenta_client::Error::Discovery(_)),
        "{err:?}"
    );
    assert!(err.to_string().contains("404"), "{err}");
}
