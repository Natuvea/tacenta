//! Two clients hold a conversation through the facade — the whole flow the
//! demo orchestrates by hand, in a handful of calls. Alice's first message
//! reaches Bob as a first contact (no prior session), decrypted and
//! attributed to Alice by the relay; Bob replies and Alice receives it.

use std::net::{IpAddr, Ipv4Addr};

use tacenta_client::{Config, DefaultClient};
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

#[tokio::test]
async fn two_clients_hold_a_conversation() {
    let (directory, relay) = start_server().await;

    let mut alice = DefaultClient::connect(&Config {
        directory,
        relay,
        user: "+alice".into(),
        device: 1,
    })
    .await
    .unwrap();
    let mut bob = DefaultClient::connect(&Config {
        directory,
        relay,
        user: "+bob".into(),
        device: 1,
    })
    .await
    .unwrap();

    let alice_addr = alice.address().clone();
    let bob_addr = bob.address().clone();

    // Alice sends to Bob — a first contact, no session yet. Bob receives it
    // decrypted, attributed to Alice, without having been told the sender.
    alice
        .send(&bob_addr, b"meet at the north dock")
        .await
        .unwrap();
    let inbox = bob.receive().await.unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].from, alice_addr);
    assert_eq!(inbox[0].plaintext, b"meet at the north dock");

    // Bob replies over the session Bob's decrypt established; Alice receives.
    bob.send(&alice_addr, b"understood").await.unwrap();
    let inbox = alice.receive().await.unwrap();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].from, bob_addr);
    assert_eq!(inbox[0].plaintext, b"understood");
}

#[tokio::test]
async fn inbound_streams_messages_one_at_a_time() {
    use futures_util::StreamExt;

    let (directory, relay) = start_server().await;
    let mut alice = DefaultClient::connect(&Config {
        directory,
        relay,
        user: "+alice".into(),
        device: 1,
    })
    .await
    .unwrap();
    let mut bob = DefaultClient::connect(&Config {
        directory,
        relay,
        user: "+bob".into(),
        device: 1,
    })
    .await
    .unwrap();
    let bob_addr = bob.address().clone();

    // Two messages queued before Bob looks: whether the relay hands them
    // over as one batch or two, the stream yields them singly, in order.
    alice.send(&bob_addr, b"one").await.unwrap();
    alice.send(&bob_addr, b"two").await.unwrap();
    {
        let mut inbound = std::pin::pin!(bob.inbound());
        let first = inbound.next().await.unwrap().unwrap();
        let second = inbound.next().await.unwrap().unwrap();
        assert_eq!(first.plaintext, b"one");
        assert_eq!(second.plaintext, b"two");
    }

    // The stream borrowed the client; after it, the client is usable again.
    alice.send(&bob_addr, b"three").await.unwrap();
    let mut inbound = std::pin::pin!(bob.inbound());
    assert_eq!(inbound.next().await.unwrap().unwrap().plaintext, b"three");
}

#[tokio::test]
async fn sending_to_an_unregistered_peer_is_an_error() {
    let (directory, relay) = start_server().await;
    let mut alice = DefaultClient::connect(&Config {
        directory,
        relay,
        user: "+alice".into(),
        device: 1,
    })
    .await
    .unwrap();

    // Nobody registered "+ghost"; the directory lookup finds nothing.
    let result = alice
        .send(&tacenta_client::DeviceAddr::new("+ghost", 1), b"anyone?")
        .await;
    assert!(result.is_err());
}
