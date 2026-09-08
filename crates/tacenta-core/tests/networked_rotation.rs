//! Identity rotation over the directory socket: a client rotates its bound
//! key along a continuity chain, and a third party cannot rotate an address
//! it does not control — the same trust model as the in-process test
//! (`identity_rotation.rs`), now driven over a real connection.

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

/// Real signature verification: `signature` over `message` by `identity`.
/// Serves both proof of possession (message = challenge) and rotation
/// authorization (message = challenge ++ new_identity).
struct PossessionCheck;
impl Possession for PossessionCheck {
    fn challenge(&self) -> Vec<u8> {
        let mut c = vec![0u8; 32];
        rand::rngs::OsRng.unwrap_err().fill_bytes(&mut c);
        c
    }
    fn verify(&self, identity: &[u8], message: &[u8], signature: &[u8]) -> bool {
        tacenta_core::crypto::verify_challenge(identity, message, signature)
    }
}

fn material(party: &mut DefaultProvider) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let bundle = now(CryptoProvider::publish_bundle(party, &mut rng)).unwrap();
    (CryptoProvider::identity_key(party), bundle)
}

#[tokio::test]
async fn rotation_over_the_directory_socket() {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let bob = DeviceAddr::new("+bob", 1);
    let mut key_a = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    let mut key_b = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    let (id_a, bundle_a) = material(&mut key_a);
    let (id_b, bundle_b) = material(&mut key_b);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_directory(
        listener,
        dir_server(Arc::new(Mutex::new(Directory::new())), PossessionCheck),
    ));
    let mut conn = DirConnection::connect(addr).await.unwrap();

    // Bob registers key A.
    assert_eq!(
        conn.register(&bob, id_a.clone(), bundle_a, |ch| key_a
            .sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err()))
            .await
            .unwrap(),
        DirResponse::Registered
    );

    // Rotate A → B: possession of B, authorized by the bound key A.
    let outcome = conn
        .rotate(
            &bob,
            id_b.clone(),
            bundle_b,
            |ch| key_b.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err()),
            |stmt| key_a.sign_challenge(stmt, &mut rand::rngs::OsRng.unwrap_err()),
        )
        .await
        .unwrap();
    assert_eq!(outcome, DirResponse::Rotated);
    let DirResponse::Found { identity, .. } = conn.lookup(&bob).await.unwrap() else {
        panic!("bob is bound");
    };
    assert_eq!(identity, id_b, "the binding now holds key B");

    // A third party cannot rotate Bob's address: Mallory can prove
    // possession of her own key but cannot authorize with the bound key.
    let mut mallory = DefaultProvider::generate("+mallory", 1, &mut rng).unwrap();
    let (m_id, m_bundle) = material(&mut mallory);
    let outcome = conn
        .rotate(
            &bob,
            m_id.clone(),
            m_bundle,
            |ch| mallory.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err()),
            |stmt| mallory.sign_challenge(stmt, &mut rand::rngs::OsRng.unwrap_err()),
        )
        .await
        .unwrap();
    assert_eq!(outcome, DirResponse::Unauthorized);
    let DirResponse::Found { identity, .. } = conn.lookup(&bob).await.unwrap() else {
        panic!("bob is still bound");
    };
    assert_eq!(identity, id_b, "Bob keeps his address");

    // Rotating an unregistered address is refused (possession of the new
    // key still checked first, then no binding to rotate).
    let ghost = DeviceAddr::new("+ghost", 1);
    let (id_c, bundle_c) = material(&mut key_b);
    let outcome = conn
        .rotate(
            &ghost,
            id_c,
            bundle_c,
            |ch| key_b.sign_challenge(ch, &mut rand::rngs::OsRng.unwrap_err()),
            |stmt| key_b.sign_challenge(stmt, &mut rand::rngs::OsRng.unwrap_err()),
        )
        .await
        .unwrap();
    assert_eq!(outcome, DirResponse::Unregistered);
}
