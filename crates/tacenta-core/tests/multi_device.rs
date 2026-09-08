//! Multi-device fan-out: a message to a *user* reaches all of that
//! user's devices, each through its own end-to-end encrypted session.
//!
//! End-to-end encryption is per device — a message to a user is
//! encrypted separately for each device's session, so the sender fans
//! out: it looks up the user's devices in the directory, opens a session
//! with each, and sends a distinct ciphertext to each device's queue
//! (decision record 0011). Every device then receives and decrypts
//! independently. This exercises the directory's per-user device index
//! together with the per-device delivery queues the `User` machine is
//! proven to model.

use futures_util::FutureExt;
use rand::{RngCore as _, TryRngCore as _};
use std::sync::Arc;
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};
use tacenta_directory::Directory;
use tacenta_relay::{DeviceAddr, Relay, Request, Response, decode_response, encode_request};
use tacenta_transport::{Authenticator, Connection, serve, server};
use tacenta_wire::{Envelope, Kind};

fn now<T>(fut: impl std::future::Future<Output = T>) -> T {
    fut.now_or_never()
        .expect("in-memory protocol store future did not complete synchronously")
}

struct IdentityAuth {
    directory: Arc<Directory>,
}

impl Authenticator for IdentityAuth {
    fn challenge(&self) -> Vec<u8> {
        let mut c = vec![0u8; 32];
        rand::rngs::OsRng.unwrap_err().fill_bytes(&mut c);
        c
    }
    fn verify(&self, device: &DeviceAddr, challenge: &[u8], signature: &[u8]) -> bool {
        self.directory.identity(device).is_some_and(|bytes| {
            tacenta_core::crypto::verify_challenge(bytes, challenge, signature)
        })
    }
}

/// Register a party (identity + published bundle) in the directory.
fn register(directory: &mut Directory, route: &DeviceAddr, party: &mut DefaultProvider) {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let bundle = now(CryptoProvider::publish_bundle(party, &mut rng)).unwrap();
    directory.register(route, CryptoProvider::identity_key(party), bundle.clone());
}

/// Poll a device's queue over its connection, decrypt the one pending
/// message from `peer`, and acknowledge.
async fn receive_one(
    conn: &mut Connection,
    device: &mut DefaultProvider,
    peer_c: &tacenta_core::crypto::Address,
    self_route: &DeviceAddr,
) -> Vec<u8> {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let poll = encode_request(&Request::Poll {
        device: self_route.clone(),
    });
    let Some(Response::Delivered { from, messages }) =
        decode_response(&conn.request(&poll).await.unwrap())
    else {
        panic!("expected Delivered");
    };
    assert_eq!(messages.len(), 1);
    let plaintext = now(CryptoProvider::decrypt(
        device,
        peer_c,
        &messages[0].envelope.payload,
        &mut rng,
    ))
    .unwrap();
    let ack = encode_request(&Request::Ack {
        device: self_route.clone(),
        up_to: from + 1,
    });
    assert_eq!(
        decode_response(&conn.request(&ack).await.unwrap()),
        Some(Response::Acked { accepted: true })
    );
    plaintext
}

#[tokio::test]
async fn message_to_a_user_fans_out_to_every_device() {
    let mut rng = rand::rngs::OsRng.unwrap_err();

    // Alice, and Bob on two devices.
    let mut alice = DefaultProvider::generate("+alice", 1, &mut rng).unwrap();
    let mut bob1 = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    let mut bob2 = DefaultProvider::generate("+bob", 2, &mut rng).unwrap();
    let alice_r = DeviceAddr::new("+alice", 1);
    let bob1_r = DeviceAddr::new("+bob", 1);
    let bob2_r = DeviceAddr::new("+bob", 2);

    // Everyone registers in the directory.
    let mut directory = Directory::new();
    register(&mut directory, &alice_r, &mut alice);
    register(&mut directory, &bob1_r, &mut bob1);
    register(&mut directory, &bob2_r, &mut bob2);
    let directory = Arc::new(directory);
    assert_eq!(directory.devices_of("+bob"), &[1, 2]);

    // Server + connections.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(
        listener,
        server(
            Relay::new(),
            IdentityAuth {
                directory: directory.clone(),
            },
        ),
    ));
    let mut alice_conn = Connection::connect_as(addr, &alice_r, |ch| {
        alice.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
    })
    .await
    .unwrap();
    let mut bob1_conn = Connection::connect_as(addr, &bob1_r, |ch| {
        bob1.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
    })
    .await
    .unwrap();
    let mut bob2_conn = Connection::connect_as(addr, &bob2_r, |ch| {
        bob2.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
    })
    .await
    .unwrap();

    // Alice sends one logical message to the user "+bob": fan out over
    // every device the directory lists, a distinct ciphertext each.
    let message = b"team, the plan is a go";
    for device_id in directory.devices_of("+bob").to_vec() {
        let route = DeviceAddr::new("+bob", device_id);
        let peer_c =
            tacenta_core::crypto::Address::new("+bob".to_owned(), device_id.try_into().unwrap());
        // Open a session with this device from its published bundle.
        let bundle = directory.bundle(&route).unwrap();
        now(CryptoProvider::establish_session(
            &mut alice, &peer_c, bundle, &mut rng,
        ))
        .unwrap();
        let framed = now(CryptoProvider::encrypt(
            &mut alice, &peer_c, message, &mut rng,
        ))
        .unwrap();
        let send = encode_request(&Request::Send {
            to: route,
            envelope: Envelope {
                kind: Kind::Dm,
                payload: framed,
            },
        });
        assert_eq!(
            decode_response(&alice_conn.request(&send).await.unwrap()),
            Some(Response::Ok)
        );
    }

    // Both of Bob's devices are pushed, then each independently recovers
    // the same plaintext from its own session.
    bob1_conn
        .next_notification()
        .await
        .expect("push to device 1");
    bob2_conn
        .next_notification()
        .await
        .expect("push to device 2");
    assert_eq!(
        receive_one(
            &mut bob1_conn,
            &mut bob1,
            &CryptoProvider::address(&alice),
            &bob1_r
        )
        .await,
        message
    );
    assert_eq!(
        receive_one(
            &mut bob2_conn,
            &mut bob2,
            &CryptoProvider::address(&alice),
            &bob2_r
        )
        .await,
        message
    );
}
