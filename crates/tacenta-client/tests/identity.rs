//! Persistent identity: a client saves its identity secret, and on a later
//! run reconnects under the *same* bound identity instead of generating a
//! new one. The value is proven by contrast — a fresh identity for an
//! address that is already bound is refused by trust-on-first-use, so
//! without the saved secret a returning client would be locked out.

use std::net::{IpAddr, Ipv4Addr};

use tacenta_client::{Config, DefaultClient, DirResponse, Error};
use tacenta_server::{Config as ServerConfig, Server};

async fn start_server() -> (std::net::SocketAddr, std::net::SocketAddr) {
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
    let directory = server.directory_addr().unwrap();
    let relay = server.relay_addr().unwrap();
    tokio::spawn(server.serve());
    (directory, relay)
}

fn config(directory: std::net::SocketAddr, relay: std::net::SocketAddr, user: &str) -> Config {
    Config {
        directory,
        relay,
        user: user.into(),
        device: 1,
    }
}

#[tokio::test]
async fn a_saved_identity_reconnects_under_the_same_binding() {
    let (directory, relay) = start_server().await;

    // First run: enrol with a fresh identity, save the secret, then "shut
    // down" (drop the client, closing its connections).
    let alice = DefaultClient::connect(&config(directory, relay, "+alice"))
        .await
        .unwrap();
    let alice_addr = alice.address().clone();
    let saved = alice.export_identity();
    drop(alice);

    // Later run: reconnect with the saved identity. Success proves the client
    // presented the *same* identity key — the directory refreshed the binding
    // rather than rejecting a new key for the address.
    let mut alice =
        DefaultClient::connect_with_identity(&config(directory, relay, "+alice"), &saved)
            .await
            .unwrap();
    assert_eq!(alice.address(), &alice_addr);

    // A fresh peer can still reach the reconnected identity end to end.
    let mut bob = DefaultClient::connect(&config(directory, relay, "+bob"))
        .await
        .unwrap();
    let bob_addr = bob.address().clone();
    alice.send(&bob_addr, b"back on my own key").await.unwrap();
    let inbox = bob.receive().await.unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].from, alice_addr);
    assert_eq!(inbox[0].plaintext, b"back on my own key");

    // The contrast: a returning client *without* the saved secret generates a
    // new identity, which trust-on-first-use refuses for the bound address.
    let fresh = DefaultClient::connect(&config(directory, relay, "+alice"))
        .await
        .map(|_| ());
    assert!(
        matches!(fresh, Err(Error::Directory(DirResponse::Rejected))),
        "a fresh identity for a bound address must be rejected, got {fresh:?}",
    );
}

#[tokio::test]
async fn an_exported_identity_round_trips() {
    let (directory, relay) = start_server().await;
    let alice = DefaultClient::connect(&config(directory, relay, "+alice"))
        .await
        .unwrap();
    let first = alice.export_identity();
    drop(alice);

    // Re-exporting after a reconnect yields the same secret: identity export
    // is stable, not regenerated per connect.
    let alice = DefaultClient::connect_with_identity(&config(directory, relay, "+alice"), &first)
        .await
        .unwrap();
    assert_eq!(alice.export_identity(), first);
}
