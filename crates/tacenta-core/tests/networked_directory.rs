//! The directory as a networked service: register and look up public key
//! material over a real TCP socket, with the full trust model enforced on
//! the wire.
//!
//! A registrant proves possession of the identity key it submits by
//! signing the connection's challenge; the server verifies with real
//! open-tacenta crypto (the injected `Possession`), then the directory
//! applies trust on first use. The test drives a genuine client against a
//! genuine server and checks: a first registration succeeds, a same-key
//! re-registration refreshes, both wire-level attacks are turned away
//! (hijacking a bound address, impersonating an identity), and a peer's
//! lookup returns a bundle that actually opens an encrypted session.

use futures_util::FutureExt;
use rand::{RngCore as _, TryRngCore as _};
use std::sync::{Arc, Mutex};
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};
use tacenta_directory::{DirResponse, Directory};
use tacenta_relay::DeviceAddr;
use tacenta_transport::{DirConnection, Possession, dir_server, serve_directory};

fn now<T>(fut: impl std::future::Future<Output = T>) -> T {
    fut.now_or_never()
        .expect("in-memory protocol store future did not complete synchronously")
}

/// Real proof-of-possession: the submitted identity key must have signed
/// the challenge. This is the cryptographic half of registration trust,
/// injected into the crypto-free transport.
struct PossessionCheck;
impl Possession for PossessionCheck {
    fn challenge(&self) -> Vec<u8> {
        let mut c = vec![0u8; 32];
        rand::rngs::OsRng.unwrap_err().fill_bytes(&mut c);
        c
    }
    fn verify(&self, identity: &[u8], challenge: &[u8], signature: &[u8]) -> bool {
        tacenta_core::crypto::verify_challenge(identity, challenge, signature)
    }
}

/// A party's registration material: its identity key bytes and a freshly
/// published prekey bundle, both as opaque bytes.
fn material(party: &mut DefaultProvider) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let bundle = now(CryptoProvider::publish_bundle(party, &mut rng)).unwrap();
    (CryptoProvider::identity_key(party), bundle)
}

#[tokio::test]
async fn directory_service_over_tcp_enforces_the_trust_model() {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let mut alice = DefaultProvider::generate("+alice", 1, &mut rng).unwrap();
    let mut bob = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    let mut mallory = DefaultProvider::generate("+mallory", 1, &mut rng).unwrap();
    let bob_addr = DeviceAddr::new("+bob", 1);

    // Start the directory service.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_directory(
        listener,
        dir_server(Arc::new(Mutex::new(Directory::new())), PossessionCheck),
    ));

    // Bob registers his address with his own key, proving possession.
    let (bob_identity, bob_bundle) = material(&mut bob);
    let mut bob_conn = DirConnection::connect(addr).await.unwrap();
    let outcome = bob_conn
        .register(&bob_addr, bob_identity.clone(), bob_bundle, |ch| {
            bob.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
        })
        .await
        .unwrap();
    assert_eq!(outcome, DirResponse::Registered);

    // A same-key re-registration refreshes the bundle.
    let (_, fresh_bundle) = material(&mut bob);
    let outcome = bob_conn
        .register(&bob_addr, bob_identity.clone(), fresh_bundle, |ch| {
            bob.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
        })
        .await
        .unwrap();
    assert_eq!(outcome, DirResponse::Refreshed);

    // Attack 1 — hijack a bound address. Mallory proves possession of her
    // own key but aims it at Bob's address; trust on first use rejects it.
    let (mallory_identity, mallory_bundle) = material(&mut mallory);
    let mut mallory_conn = DirConnection::connect(addr).await.unwrap();
    let outcome = mallory_conn
        .register(&bob_addr, mallory_identity, mallory_bundle, |ch| {
            mallory.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err())
        })
        .await
        .unwrap();
    assert_eq!(outcome, DirResponse::Rejected);

    // Attack 2 — impersonate an identity. Mallory submits Bob's identity
    // key for a fresh address but cannot sign with Bob's private key;
    // proof of possession rejects it before the directory is consulted.
    let (_, some_bundle) = material(&mut mallory);
    let outcome = mallory_conn
        .register(
            &DeviceAddr::new("+mallory", 2),
            bob_identity.clone(),
            some_bundle,
            |ch| mallory.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err()),
        )
        .await
        .unwrap();
    assert_eq!(outcome, DirResponse::PossessionFailed);

    // Alice looks Bob up and gets his bundle; an unknown lookup is NotFound.
    let mut alice_conn = DirConnection::connect(addr).await.unwrap();
    assert_eq!(
        alice_conn
            .lookup(&DeviceAddr::new("+nobody", 1))
            .await
            .unwrap(),
        DirResponse::NotFound
    );
    let DirResponse::Found { identity, bundle } = alice_conn.lookup(&bob_addr).await.unwrap()
    else {
        panic!("expected Bob's material");
    };
    assert_eq!(identity, bob_identity);

    // The looked-up bundle actually opens an encrypted session: Alice
    // establishes from it and encrypts, and Bob decrypts.
    now(CryptoProvider::establish_session(
        &mut alice,
        &CryptoProvider::address(&bob),
        &bundle,
        &mut rng,
    ))
    .unwrap();
    let message = b"found you in the directory";
    let ciphertext = now(CryptoProvider::encrypt(
        &mut alice,
        &CryptoProvider::address(&bob),
        message,
        &mut rng,
    ))
    .unwrap();
    let plaintext = now(CryptoProvider::decrypt(
        &mut bob,
        &CryptoProvider::address(&alice),
        &ciphertext,
        &mut rng,
    ))
    .unwrap();
    assert_eq!(plaintext, message);
}
