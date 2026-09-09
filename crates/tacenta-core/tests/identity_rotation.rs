//! Authorized identity rotation: an address's bound identity key can be
//! replaced, but only by the key that currently controls it — key
//! continuity, the same shape as a key-fingerprint change in a messaging app.
//!
//! Admitting a rotation takes two cryptographic checks, then the crypto-free
//! `Directory::rotate`:
//!
//! 1. **Proof of possession of the new key** — the new identity key signs
//!    the server challenge, so you cannot rotate to a key you do not hold.
//! 2. **Authorization by the currently bound key** — the *old* key (the one
//!    the directory holds now) signs a statement binding the new key, so
//!    only whoever controls the address today can hand it to a new key.
//!
//! The load-bearing property is that authorization is checked against the
//! *current* binding, not any past one: rotation forms a chain A → B → C
//! where each step is blessed by its immediate predecessor, and a
//! superseded key can no longer authorize anything. A third party, unable
//! to sign with the current key, cannot take the address over.

use futures_util::FutureExt;
use rand::TryRngCore as _;
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};
use tacenta_directory::{Directory, Rotation};
use tacenta_relay::DeviceAddr;

fn now<T>(fut: impl std::future::Future<Output = T>) -> T {
    fut.now_or_never()
        .expect("in-memory protocol store future did not complete synchronously")
}

#[derive(Debug, PartialEq, Eq)]
enum Admission {
    Rotated,
    /// The new key's possession signature did not verify.
    PossessionFailed,
    /// The rotation was not authorized by the currently bound key.
    Unauthorized,
    /// The address is not registered, so there is no binding to rotate.
    Unregistered,
}

/// A server admitting an identity rotation: prove possession of the new
/// key, verify the rotation is authorized by the currently bound key, then
/// let the directory replace the binding.
fn admit_rotation(
    directory: &mut Directory,
    device: &DeviceAddr,
    new_identity: Vec<u8>,
    new_bundle: Vec<u8>,
    challenge: &[u8],
    possession_sig: &[u8],
    rotation_sig: &[u8],
) -> Admission {
    let Some(current_identity) = directory.identity(device).map(<[u8]>::to_vec) else {
        return Admission::Unregistered;
    };

    // 1. Possession of the new key.
    if !tacenta_core::crypto::verify_challenge(&new_identity, challenge, possession_sig) {
        return Admission::PossessionFailed;
    }

    // 2. Authorization by the *current* key over the new identity.
    let mut statement = challenge.to_vec();
    statement.extend_from_slice(&new_identity);
    if !tacenta_core::crypto::verify_challenge(&current_identity, &statement, rotation_sig) {
        return Admission::Unauthorized;
    }

    match directory.rotate(device, new_identity, new_bundle) {
        Rotation::Rotated => Admission::Rotated,
        Rotation::Unregistered => Admission::Unregistered,
    }
}

/// A party's identity bytes and a freshly published bundle.
fn material(party: &mut DefaultProvider) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let bundle = now(CryptoProvider::publish_bundle(party, &mut rng)).unwrap();
    (CryptoProvider::identity_key(party), bundle)
}

/// Sign a rotation authorization with `authorizer`: its signature over
/// `challenge ++ new_identity`.
fn authorize(authorizer: &DefaultProvider, challenge: &[u8], new_identity: &[u8]) -> Vec<u8> {
    let mut statement = challenge.to_vec();
    statement.extend_from_slice(new_identity);
    authorizer.sign_challenge(&statement, &mut rand::rngs::OsRng.unwrap_err())
}

#[test]
fn an_address_rotates_along_a_chain_of_its_own_keys() {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let mut directory = Directory::new();
    let bob = DeviceAddr::new("+bob", 1);

    // Bob is bound to key A.
    let mut key_a = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    let (id_a, bundle_a) = material(&mut key_a);
    directory.register(&bob, id_a.clone(), bundle_a);

    // Rotate A → B, authorized by A.
    let mut key_b = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    let (id_b, bundle_b) = material(&mut key_b);
    let challenge = b"server-nonce-1";
    assert_eq!(
        admit_rotation(
            &mut directory,
            &bob,
            id_b.clone(),
            bundle_b,
            challenge,
            &key_b.sign_challenge(challenge, &mut rng), // possession of B
            &authorize(&key_a, challenge, &id_b),       // A authorizes
        ),
        Admission::Rotated
    );
    assert_eq!(directory.identity(&bob), Some(&id_b[..]));

    // Rotate B → C, authorized by B (the chain continues).
    let mut key_c = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    let (id_c, bundle_c) = material(&mut key_c);
    let challenge = b"server-nonce-2";
    assert_eq!(
        admit_rotation(
            &mut directory,
            &bob,
            id_c.clone(),
            bundle_c,
            challenge,
            &key_c.sign_challenge(challenge, &mut rng),
            &authorize(&key_b, challenge, &id_c),
        ),
        Admission::Rotated
    );
    assert_eq!(directory.identity(&bob), Some(&id_c[..]));

    // A superseded key can no longer authorize: A tries to rotate C → some
    // new key, but A is two rotations stale. Only the current key (C) may.
    let mut usurper = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    let (id_x, bundle_x) = material(&mut usurper);
    let challenge = b"server-nonce-3";
    assert_eq!(
        admit_rotation(
            &mut directory,
            &bob,
            id_x.clone(),
            bundle_x,
            challenge,
            &usurper.sign_challenge(challenge, &mut rng), // possession fine
            &authorize(&key_a, challenge, &id_x),         // but A is stale
        ),
        Admission::Unauthorized
    );
    assert_eq!(
        directory.identity(&bob),
        Some(&id_c[..]),
        "binding unchanged"
    );
}

#[test]
fn a_third_party_cannot_rotate_an_address_it_does_not_control() {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let mut directory = Directory::new();
    let bob = DeviceAddr::new("+bob", 1);

    let mut bob_key = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    let (bob_id, bob_bundle) = material(&mut bob_key);
    directory.register(&bob, bob_id.clone(), bob_bundle);

    // Mallory holds her own key and can prove possession of it, but she
    // cannot sign the rotation with Bob's currently bound key.
    let mut mallory = DefaultProvider::generate("+mallory", 1, &mut rng).unwrap();
    let (mallory_id, mallory_bundle) = material(&mut mallory);
    let challenge = b"server-nonce";
    assert_eq!(
        admit_rotation(
            &mut directory,
            &bob,
            mallory_id.clone(),
            mallory_bundle,
            challenge,
            &mallory.sign_challenge(challenge, &mut rng), // possession of her own key
            &authorize(&mallory, challenge, &mallory_id), // authorized by the wrong key
        ),
        Admission::Unauthorized
    );
    assert_eq!(
        directory.identity(&bob),
        Some(&bob_id[..]),
        "Bob keeps his address"
    );
}
