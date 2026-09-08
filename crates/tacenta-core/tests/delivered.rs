//! The delivered-to-user watermark over the wire: a user with two devices
//! that have acked different amounts learns how far *all* of them have
//! caught up — the minimum cursor, the `User` machine's `delivered`
//! computed live on the relay (decision record 0026).

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

fn register(directory: &mut Directory, route: &DeviceAddr, party: &mut DefaultProvider) {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let bundle = now(CryptoProvider::publish_bundle(party, &mut rng)).unwrap();
    directory.register(route, CryptoProvider::identity_key(party), bundle.clone());
}

fn env(byte: u8) -> Envelope {
    Envelope {
        kind: Kind::Dm,
        payload: vec![byte],
    }
}

#[tokio::test]
async fn a_user_learns_its_delivered_watermark() {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let mut alice = DefaultProvider::generate("+alice", 1, &mut rng).unwrap();
    let mut bob1 = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    let mut bob2 = DefaultProvider::generate("+bob", 2, &mut rng).unwrap();
    let alice_r = DeviceAddr::new("+alice", 1);
    let bob1_r = DeviceAddr::new("+bob", 1);
    let bob2_r = DeviceAddr::new("+bob", 2);

    let mut directory = Directory::new();
    register(&mut directory, &alice_r, &mut alice);
    register(&mut directory, &bob1_r, &mut bob1);
    register(&mut directory, &bob2_r, &mut bob2);
    let directory = Arc::new(directory);

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

    // Alice fans three messages to each of Bob's two devices.
    for route in [&bob1_r, &bob2_r] {
        for b in 0..3u8 {
            let resp = alice_conn
                .request(&encode_request(&Request::Send {
                    to: route.clone(),
                    envelope: env(b),
                }))
                .await
                .unwrap();
            assert_eq!(decode_response(&resp), Some(Response::Ok));
        }
    }

    // Device 1 acks all three; device 2 acks one (via its own connection).
    let mut bob2_conn = Connection::connect_as(addr, &bob2_r, |ch| {
        bob2.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
    })
    .await
    .unwrap();
    let ack = |device: DeviceAddr, up_to: u64| encode_request(&Request::Ack { device, up_to });
    assert_eq!(
        decode_response(&bob1_conn.request(&ack(bob1_r.clone(), 3)).await.unwrap()),
        Some(Response::Acked { accepted: true })
    );
    assert_eq!(
        decode_response(&bob2_conn.request(&ack(bob2_r.clone(), 1)).await.unwrap()),
        Some(Response::Acked { accepted: true })
    );

    // Bob's device asks how far *all* his devices have caught up: min(3,1)=1.
    let resp = bob1_conn
        .request(&encode_request(&Request::Delivered {
            devices: vec![bob1_r.clone(), bob2_r.clone()],
        }))
        .await
        .unwrap();
    assert_eq!(
        decode_response(&resp),
        Some(Response::DeliveredCount { count: 1 })
    );

    // Querying across another user's device is refused.
    let resp = bob1_conn
        .request(&encode_request(&Request::Delivered {
            devices: vec![bob1_r.clone(), DeviceAddr::new("+alice", 1)],
        }))
        .await
        .unwrap();
    assert_eq!(decode_response(&resp), Some(Response::Unauthorized));
}
