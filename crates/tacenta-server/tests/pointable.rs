//! A client points at a running server: register over the directory,
//! authenticate to the relay against that registration, route a message,
//! and confirm an unregistered device cannot authenticate.

use futures_util::FutureExt;
use rand::TryRngCore as _;
use std::net::{IpAddr, Ipv4Addr};
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};
use tacenta_directory::DirResponse;
use tacenta_relay::{
    DeviceAddr, Request, Response, StoredMessage, decode_response, encode_request,
};
use tacenta_server::{Config, Server};
use tacenta_transport::{Connection, DirConnection};
use tacenta_wire::{Envelope, Kind};

fn now<T>(fut: impl std::future::Future<Output = T>) -> T {
    fut.now_or_never()
        .expect("in-memory protocol store future did not complete synchronously")
}

#[tokio::test]
async fn a_client_points_at_a_running_server() {
    // Bind on ephemeral ports and serve in the background.
    let config = Config {
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
    };
    let server = Server::bind(&config).await.unwrap();
    let dir_addr = server.directory_addr().unwrap();
    let relay_addr = server.relay_addr().unwrap();
    tokio::spawn(server.serve());

    let mut rng = rand::rngs::OsRng.unwrap_err();
    let mut alice = DefaultProvider::generate("+alice", 1, &mut rng).unwrap();
    let alice_r = DeviceAddr::new("+alice", 1);

    // Register over the directory socket, proving possession.
    let bundle = now(CryptoProvider::publish_bundle(&mut alice, &mut rng)).unwrap();
    let mut dir = DirConnection::connect(dir_addr).await.unwrap();
    let outcome = dir
        .register(
            &alice_r,
            CryptoProvider::identity_key(&alice),
            bundle.clone(),
            |ch| alice.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err()),
        )
        .await
        .unwrap();
    assert_eq!(outcome, DirResponse::Registered);

    // Authenticate to the relay — the server verifies the signature
    // against the identity the directory now holds.
    let mut conn = Connection::connect_as(relay_addr, &alice_r, |ch| {
        alice.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
    })
    .await
    .unwrap();

    // Route an (opaque) envelope through the relay and read it back.
    let envelope = Envelope {
        kind: Kind::Dm,
        payload: b"opaque to the server".to_vec(),
    };
    let resp = conn
        .request(&encode_request(&Request::Send {
            to: alice_r.clone(),
            envelope: envelope.clone(),
        }))
        .await
        .unwrap();
    assert_eq!(decode_response(&resp), Some(Response::Ok));

    let resp = conn
        .request(&encode_request(&Request::Poll {
            device: alice_r.clone(),
        }))
        .await
        .unwrap();
    assert_eq!(
        decode_response(&resp),
        Some(Response::Delivered {
            from: 0,
            messages: vec![StoredMessage {
                from: alice_r.clone(),
                envelope
            }],
        })
    );

    // An unregistered device cannot authenticate to the relay: the shared
    // directory has no identity for it, so the handshake is refused.
    let mallory = DefaultProvider::generate("+mallory", 1, &mut rng).unwrap();
    let mallory_r = DeviceAddr::new("+mallory", 1);
    let result = Connection::connect_as(relay_addr, &mallory_r, |ch| {
        mallory.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
    })
    .await;
    assert!(result.is_err());
}
