//! Lost-key recovery over the directory socket: a device provisions a
//! recovery key (its private half kept offline), and later — with its
//! identity key lost — re-keys by authorizing the rotation with the
//! recovery key instead of the lost one. A third party, holding neither
//! the current identity key nor the recovery key, can do neither.

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

fn sign(party: &DefaultProvider, message: &[u8]) -> Vec<u8> {
    party.sign_challenge(message, &mut rand::rngs::OsRng.unwrap_err())
}

#[tokio::test]
async fn a_lost_key_is_recovered_with_the_recovery_key() {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let bob = DeviceAddr::new("+bob", 1);
    let mut key_a = DefaultProvider::generate("+bob", 1, &mut rng).unwrap(); // original identity
    let recovery = DefaultProvider::generate("+bob", 1, &mut rng).unwrap(); // recovery keypair (offline)
    let mut key_b = DefaultProvider::generate("+bob", 1, &mut rng).unwrap(); // the new identity
    let recovery_key = CryptoProvider::identity_key(&recovery);
    let (id_a, bundle_a) = material(&mut key_a);
    let (id_b, bundle_b) = material(&mut key_b);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(serve_directory(
        listener,
        dir_server(Arc::new(Mutex::new(Directory::new())), PossessionCheck),
    ));
    let mut conn = DirConnection::connect(addr).await.unwrap();

    // Bob registers key A, then provisions a recovery key (authorized by A).
    assert_eq!(
        conn.register(&bob, id_a.clone(), bundle_a, |ch| sign(&key_a, ch))
            .await
            .unwrap(),
        DirResponse::Registered
    );
    assert_eq!(
        conn.set_recovery(&bob, recovery_key.clone(), |ch| sign(&key_a, ch))
            .await
            .unwrap(),
        DirResponse::RecoverySet
    );

    // Bob's device — and key A with it — is lost. He re-keys to B, proving
    // possession of B and authorizing with the recovery key.
    let outcome = conn
        .recover(
            &bob,
            id_b.clone(),
            bundle_b,
            |ch| sign(&key_b, ch),
            |stmt| sign(&recovery, stmt),
        )
        .await
        .unwrap();
    assert_eq!(outcome, DirResponse::Rotated);
    let DirResponse::Found { identity, .. } = conn.lookup(&bob).await.unwrap() else {
        panic!("bob is bound");
    };
    assert_eq!(identity, id_b, "the binding now holds the recovered key B");

    // A third party can neither set a recovery key (needs the current key,
    // now B) nor recover (needs the recovery key).
    let mut mallory = DefaultProvider::generate("+mallory", 1, &mut rng).unwrap();
    let (m_id, m_bundle) = material(&mut mallory);
    assert_eq!(
        conn.set_recovery(&bob, m_id.clone(), |ch| sign(&mallory, ch))
            .await
            .unwrap(),
        DirResponse::Unauthorized
    );
    let outcome = conn
        .recover(
            &bob,
            m_id,
            m_bundle,
            |ch| sign(&mallory, ch),
            |stmt| sign(&mallory, stmt),
        )
        .await
        .unwrap();
    assert_eq!(outcome, DirResponse::Unauthorized);
    let DirResponse::Found { identity, .. } = conn.lookup(&bob).await.unwrap() else {
        panic!("bob is still bound");
    };
    assert_eq!(identity, id_b, "Bob keeps his address");

    // Recovering an address with no recovery key set is refused.
    let carol = DeviceAddr::new("+carol", 1);
    let mut key_c = DefaultProvider::generate("+carol", 1, &mut rng).unwrap();
    let (id_c, bundle_c) = material(&mut key_c);
    conn.register(&carol, id_c, bundle_c, |ch| sign(&key_c, ch))
        .await
        .unwrap();
    let (id_c2, bundle_c2) = material(&mut key_c);
    let outcome = conn
        .recover(
            &carol,
            id_c2,
            bundle_c2,
            |ch| sign(&key_c, ch),
            |stmt| sign(&key_c, stmt),
        )
        .await
        .unwrap();
    assert_eq!(outcome, DirResponse::NoRecovery);
}
