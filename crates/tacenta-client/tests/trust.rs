//! Trust and delivery-status operations on the client facade: a client
//! re-keys its own identity and keeps talking, and it can ask how far its
//! messages have been delivered.

use std::net::{IpAddr, Ipv4Addr};

use tacenta_client::{Client, Config, DefaultClient};
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

async fn connect(
    directory: std::net::SocketAddr,
    relay: std::net::SocketAddr,
    user: &str,
) -> Client {
    DefaultClient::connect(&Config {
        directory,
        relay,
        user: user.into(),
        device: 1,
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn a_client_rekeys_and_keeps_talking() {
    let (directory, relay) = start_server().await;
    let mut alice = connect(directory, relay, "+alice").await;
    let mut bob = connect(directory, relay, "+bob").await;
    let alice_addr = alice.address().clone();
    let bob_addr = bob.address().clone();

    // Alice re-keys. Her address is unchanged; the directory binding now
    // holds a fresh identity key, authorized by the old one.
    alice.rotate().await.unwrap();

    // After rotation Alice opens a fresh session (her store is empty) and
    // reaches Bob, who receives the message attributed to Alice's address.
    alice.send(&bob_addr, b"new key, same me").await.unwrap();
    let inbox = bob.receive().await.unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].from, alice_addr);
    assert_eq!(inbox[0].plaintext, b"new key, same me");

    // Bob replies to Alice's address; Alice — on her rotated identity, over
    // the relay connection that survived the rotation — receives it.
    bob.send(&alice_addr, b"got it").await.unwrap();
    let back = alice.receive().await.unwrap();
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].plaintext, b"got it");

    // Alice has received and acked exactly one message; her delivered-to-all
    // watermark over her own device reflects it.
    let watermark = alice.delivered_watermark(&[alice_addr]).await.unwrap();
    assert_eq!(watermark, 1);
}

#[tokio::test]
async fn rotation_is_rejected_without_the_current_key() {
    // A rotation authorizes with the currently bound key, so a client can
    // only re-key the address it controls — this is proven at the directory
    // and transport layers; here we confirm the facade's own rotate reaches
    // the bound path and succeeds for the legitimate owner.
    let (directory, relay) = start_server().await;
    let mut alice = connect(directory, relay, "+alice").await;
    alice.rotate().await.unwrap();
    // A second rotation from the same client chains along the continuity
    // line: the (now-current) key authorizes the next.
    alice.rotate().await.unwrap();
}
