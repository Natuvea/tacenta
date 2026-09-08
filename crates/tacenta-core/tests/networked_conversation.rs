//! The whole system over real network sockets.
//!
//! A relay server runs on a TCP socket. Alice and Bob each connect as
//! clients and exchange a real end-to-end encrypted conversation: the
//! protocol ciphertext, framed in a tacenta envelope, travels
//! over the socket through the request/response protocol to the
//! cryptographically blind relay, which queues it in the proven
//! per-device delivery `Session`; the recipient polls, decrypts, and
//! acknowledges — all across the network.
//!
//! This is the capstone integration: crypto (`tacenta-core`, open-tacenta),
//! transport (`tacenta-transport`, TCP), server (`tacenta-relay`, blind),
//! and the proven wire and delivery layers, working together as a
//! running networked system. Wire and delivery behavior is proven; the
//! cryptography is open-tacenta's (tested, not proven — `docs/claims.md`).

use futures_util::FutureExt;
use rand::{RngCore as _, TryRngCore as _};
use std::collections::HashMap;
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};
use tacenta_relay::{DeviceAddr, Relay, Request, Response, decode_response, encode_request};
use tacenta_transport::{Authenticator, Connection, serve, server};
use tacenta_wire::{Envelope, Kind};

fn now<T>(fut: impl std::future::Future<Output = T>) -> T {
    fut.now_or_never()
        .expect("in-memory protocol store future did not complete synchronously")
}

/// A directory-backed authenticator: it knows each device's public
/// identity key (registered out of band) and verifies the device's
/// signature over the connection challenge. This is the crypto the blind
/// transport delegates to.
struct IdentityAuth {
    registry: HashMap<DeviceAddr, Vec<u8>>,
}

impl Authenticator for IdentityAuth {
    fn challenge(&self) -> Vec<u8> {
        let mut c = vec![0u8; 32];
        rand::rngs::OsRng.unwrap_err().fill_bytes(&mut c);
        c
    }
    fn verify(&self, device: &DeviceAddr, challenge: &[u8], signature: &[u8]) -> bool {
        self.registry.get(device).is_some_and(|identity| {
            tacenta_core::crypto::verify_challenge(identity, challenge, signature)
        })
    }
}

#[tokio::test]
async fn e2ee_conversation_over_real_sockets() {
    // Crypto setup (the provider calls complete synchronously on the
    // in-memory store; `now` drives them). Bob's bundle reaches Alice
    // out of band — bundle distribution is a directory concern, separate
    // from message transport.
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let mut alice = DefaultProvider::generate("+alice", 1, &mut rng).unwrap();
    let mut bob = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    let alice_c = CryptoProvider::address(&alice);
    let bob_c = CryptoProvider::address(&bob);
    let alice_r = DeviceAddr::new("+alice", 1);
    let bob_r = DeviceAddr::new("+bob", 1);

    // The server's directory: each device's public identity key.
    let registry = HashMap::from([
        (alice_r.clone(), CryptoProvider::identity_key(&alice)),
        (bob_r.clone(), CryptoProvider::identity_key(&bob)),
    ]);

    // Start the authenticating relay server on an ephemeral local port.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve(
        listener,
        server(Relay::new(), IdentityAuth { registry }),
    ));

    // Alice and Bob each connect and authenticate as their device,
    // signing the server's challenge with their identity key.
    let mut alice_conn = Connection::connect_as(addr, &alice_r, |ch| {
        alice.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
    })
    .await
    .unwrap();
    let mut bob_conn = Connection::connect_as(addr, &bob_r, |ch| {
        bob.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
    })
    .await
    .unwrap();

    let bundle = now(CryptoProvider::publish_bundle(&mut bob, &mut rng)).unwrap();
    now(CryptoProvider::establish_session(
        &mut alice, &bob_c, &bundle, &mut rng,
    ))
    .unwrap();

    // Alice encrypts and sends over her socket.
    let framed = now(CryptoProvider::encrypt(
        &mut alice,
        &bob_c,
        b"hello across the network",
        &mut rng,
    ))
    .unwrap();
    let send = encode_request(&Request::Send {
        to: bob_r.clone(),
        envelope: Envelope {
            kind: Kind::Dm,
            payload: framed,
        },
    });
    assert_eq!(
        decode_response(&alice_conn.request(&send).await.unwrap()),
        Some(Response::Ok)
    );

    // Bob polls over his socket, decrypts, and acknowledges.
    let poll = encode_request(&Request::Poll {
        device: bob_r.clone(),
    });
    let Some(Response::Delivered { from, messages }) =
        decode_response(&bob_conn.request(&poll).await.unwrap())
    else {
        panic!("expected Delivered");
    };
    assert_eq!(messages.len(), 1);
    // The relay attributed the message to its sender, Alice.
    assert_eq!(messages[0].from, alice_r);
    let recovered = now(CryptoProvider::decrypt(
        &mut bob,
        &alice_c,
        &messages[0].envelope.payload,
        &mut rng,
    ))
    .unwrap();
    assert_eq!(recovered, b"hello across the network");

    let ack = encode_request(&Request::Ack {
        device: bob_r.clone(),
        up_to: from + messages.len() as u64,
    });
    assert_eq!(
        decode_response(&bob_conn.request(&ack).await.unwrap()),
        Some(Response::Acked { accepted: true })
    );

    // Bob replies; Alice receives it over her socket.
    let framed = now(CryptoProvider::encrypt(
        &mut bob,
        &alice_c,
        b"received, over and out",
        &mut rng,
    ))
    .unwrap();
    let send = encode_request(&Request::Send {
        to: alice_r.clone(),
        envelope: Envelope {
            kind: Kind::Dm,
            payload: framed,
        },
    });
    assert_eq!(
        decode_response(&bob_conn.request(&send).await.unwrap()),
        Some(Response::Ok)
    );

    let poll = encode_request(&Request::Poll {
        device: alice_r.clone(),
    });
    let Some(Response::Delivered { from, messages }) =
        decode_response(&alice_conn.request(&poll).await.unwrap())
    else {
        panic!("expected Delivered");
    };
    assert_eq!(messages[0].from, bob_r);
    let recovered = now(CryptoProvider::decrypt(
        &mut alice,
        &bob_c,
        &messages[0].envelope.payload,
        &mut rng,
    ))
    .unwrap();
    assert_eq!(recovered, b"received, over and out");

    let ack = encode_request(&Request::Ack {
        device: alice_r,
        up_to: from + messages.len() as u64,
    });
    assert_eq!(
        decode_response(&alice_conn.request(&ack).await.unwrap()),
        Some(Response::Acked { accepted: true })
    );
}
