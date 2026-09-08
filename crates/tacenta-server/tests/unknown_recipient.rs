//! A `Send` to an address nobody has registered must not mint a queue.
//!
//! `Relay::enqueue` creates a queue on demand for whatever address it is
//! handed, and nothing ever removes one. An authenticated client could
//! therefore mint queues for addresses that will never exist and never drain,
//! growing server memory with attacker-chosen keys.
//!
//! The refusal is in the transport, not the relay. That matters twice over: the
//! relay stays blind (it still routes to any device it is asked about, which is
//! decision 0017's property), and `tacenta-state`'s proven `Session` model --
//! `new`/`append`/`ack`/`pending` in `verification/Verification/StateRefinement.lean`
//! -- is untouched. A guard inside the relay would have reopened all four
//! theorems to fix a resource problem the proofs say nothing about.
//!
//! The second test is the one that keeps the first honest: a registered
//! recipient must still receive, or the fix would be a denial of service
//! wearing a defence's clothes.

use rand::TryRngCore as _;
use std::net::{IpAddr, Ipv4Addr};
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};
use tacenta_relay::{DeviceAddr, Request, Response, decode_response, encode_request};
use tacenta_server::{Config, Server};
use tacenta_transport::{Connection, DirConnection};
use tacenta_wire::{Envelope, Kind};

fn config() -> Config {
    Config {
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
    }
}

/// Register `party` at `addr` over the directory, so it becomes a device the
/// deployment knows about.
async fn register(dir_addr: std::net::SocketAddr, party: &mut DefaultProvider, addr: &DeviceAddr) {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let bundle = CryptoProvider::publish_bundle(party, &mut rng)
        .await
        .unwrap();
    let identity = CryptoProvider::identity_key(party);
    let mut dir = DirConnection::connect(dir_addr).await.unwrap();
    dir.register(addr, identity, bundle, |ch| {
        party.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn a_send_to_an_unregistered_address_is_refused() {
    let server = Server::bind(&config()).await.unwrap();
    let dir_addr = server.directory_addr().unwrap();
    let relay_addr = server.relay_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(server.serve_until(async move {
        let _ = stopped.await;
    }));

    let mut rng = rand::rngs::OsRng.unwrap_err();
    let sender_addr = DeviceAddr::new("sender", 1);
    let mut sender = DefaultProvider::generate("sender", 1, &mut rng).unwrap();
    register(dir_addr, &mut sender, &sender_addr).await;

    let mut conn = Connection::connect_as(relay_addr, &sender_addr, |ch| {
        sender.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
    })
    .await
    .unwrap();

    // A recipient the directory has never heard of.
    let stranger = DeviceAddr::new("nobody-has-ever-registered-this", 7);
    let resp = conn
        .request(&encode_request(&Request::Send {
            to: stranger,
            envelope: Envelope {
                kind: Kind::Dm,
                payload: b"payload".to_vec(),
            },
        }))
        .await
        .unwrap();

    assert_eq!(
        decode_response(&resp),
        Some(Response::UnknownRecipient),
        "a send to an unregistered address must not create a queue for it"
    );

    stop.send(()).unwrap();
    handle.await.unwrap().unwrap();
}

/// And delivery to a real recipient still works.
///
/// Without this the test above would pass just as well against a server that
/// refused everything.
#[tokio::test]
async fn a_send_to_a_registered_address_still_works() {
    let server = Server::bind(&config()).await.unwrap();
    let dir_addr = server.directory_addr().unwrap();
    let relay_addr = server.relay_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(server.serve_until(async move {
        let _ = stopped.await;
    }));

    let mut rng = rand::rngs::OsRng.unwrap_err();
    let sender_addr = DeviceAddr::new("sender", 1);
    let mut sender = DefaultProvider::generate("sender", 1, &mut rng).unwrap();
    register(dir_addr, &mut sender, &sender_addr).await;

    let recipient_addr = DeviceAddr::new("recipient", 1);
    let mut recipient = DefaultProvider::generate("recipient", 1, &mut rng).unwrap();
    register(dir_addr, &mut recipient, &recipient_addr).await;

    let mut conn = Connection::connect_as(relay_addr, &sender_addr, |ch| {
        sender.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
    })
    .await
    .unwrap();

    let resp = conn
        .request(&encode_request(&Request::Send {
            to: recipient_addr.clone(),
            envelope: Envelope {
                kind: Kind::Dm,
                payload: b"payload".to_vec(),
            },
        }))
        .await
        .unwrap();
    assert_eq!(
        decode_response(&resp),
        Some(Response::Ok),
        "a registered recipient must receive"
    );

    // And it is really there to collect, not merely accepted.
    let mut theirs = Connection::connect_as(relay_addr, &recipient_addr, |ch| {
        recipient.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
    })
    .await
    .unwrap();
    let polled = theirs
        .request(&encode_request(&Request::Poll {
            device: recipient_addr,
        }))
        .await
        .unwrap();
    let Some(Response::Delivered { messages, .. }) = decode_response(&polled) else {
        panic!("expected a delivery");
    };
    assert_eq!(messages.len(), 1, "the message should be waiting");

    stop.send(()).unwrap();
    handle.await.unwrap().unwrap();
}
