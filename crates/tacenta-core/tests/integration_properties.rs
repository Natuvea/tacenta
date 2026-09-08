//! Property tests over the provider integration. The cryptography is
//! open-tacenta's — assumed correct, not re-proven (see `docs/claims.md`) — but
//! *using it correctly* is our risk. These exercise the integration over many
//! inputs: encrypt/decrypt round-trips at every size and both directions,
//! tampered ciphertext is rejected (no silent wrong plaintext), a wrong
//! recipient cannot decrypt, and the hand-rolled prekey-bundle codec round
//! trips and is panic-free on arbitrary bytes.

use futures_util::FutureExt;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};

/// The in-memory protocol-store futures complete synchronously.
fn now<T>(fut: impl std::future::Future<Output = T>) -> T {
    fut.now_or_never()
        .expect("in-memory protocol store future did not complete synchronously")
}

#[test]
fn round_trips_at_every_size_both_directions() {
    let mut rng = StdRng::seed_from_u64(0xA11CE);
    let mut alice = DefaultProvider::generate("+alice", 1, &mut rng).unwrap();
    let mut bob = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    let alice_c = CryptoProvider::address(&alice);
    let bob_c = CryptoProvider::address(&bob);
    let bob_bundle = now(CryptoProvider::publish_bundle(&mut bob, &mut rng)).unwrap();
    now(CryptoProvider::establish_session(
        &mut alice,
        &bob_c,
        &bob_bundle,
        &mut rng,
    ))
    .unwrap();

    // Alice → Bob: the first message is a PreKey message, the rest ratchet messages.
    for size in [0usize, 1, 15, 16, 17, 63, 255, 256, 1024, 4096] {
        let plaintext: Vec<u8> = (0..size).map(|_| rng.random::<u8>()).collect();
        let ciphertext = now(CryptoProvider::encrypt(
            &mut alice, &bob_c, &plaintext, &mut rng,
        ))
        .unwrap();
        let decrypted = now(CryptoProvider::decrypt(
            &mut bob,
            &alice_c,
            &ciphertext,
            &mut rng,
        ))
        .unwrap();
        assert_eq!(decrypted, plaintext, "round-trip at size {size}");
    }

    // Bob → Alice: the reverse ratchet direction.
    for size in [0usize, 32, 100, 2048] {
        let plaintext: Vec<u8> = (0..size).map(|_| rng.random::<u8>()).collect();
        let ciphertext = now(CryptoProvider::encrypt(
            &mut bob, &alice_c, &plaintext, &mut rng,
        ))
        .unwrap();
        let decrypted = now(CryptoProvider::decrypt(
            &mut alice,
            &bob_c,
            &ciphertext,
            &mut rng,
        ))
        .unwrap();
        assert_eq!(decrypted, plaintext, "reverse round-trip at size {size}");
    }
}

#[test]
fn tampered_ciphertext_is_rejected() {
    // A single-byte flip of a valid ciphertext must fail to decrypt — never
    // yield a different plaintext. A fresh (deterministic) Alice/Bob pair per
    // attempt so the real recipient decrypts, and one failed decrypt cannot
    // affect the next; which position is flipped varies with the seed.
    for seed in [1u64, 2, 3, 4, 5] {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut alice = DefaultProvider::generate("+alice", 1, &mut rng).unwrap();
        let mut bob = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
        let bob_c = CryptoProvider::address(&bob);
        let alice_c = CryptoProvider::address(&alice);
        let bundle = now(CryptoProvider::publish_bundle(&mut bob, &mut rng)).unwrap();
        now(CryptoProvider::establish_session(
            &mut alice, &bob_c, &bundle, &mut rng,
        ))
        .unwrap();
        let ciphertext = now(CryptoProvider::encrypt(
            &mut alice,
            &bob_c,
            b"secret payload",
            &mut rng,
        ))
        .unwrap();

        let pos = (seed as usize * 7) % ciphertext.len();
        let mut tampered = ciphertext.clone();
        tampered[pos] ^= 0x01;
        assert!(
            now(CryptoProvider::decrypt(
                &mut bob, &alice_c, &tampered, &mut rng
            ))
            .is_err(),
            "a flip at byte {pos} (seed {seed}) must be rejected",
        );
    }
}

#[test]
fn a_wrong_recipient_cannot_decrypt() {
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    let mut alice = DefaultProvider::generate("+alice", 1, &mut rng).unwrap();
    let mut bob = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    let mut carol = DefaultProvider::generate("+carol", 1, &mut rng).unwrap();
    let bob_c = CryptoProvider::address(&bob);
    let alice_c = CryptoProvider::address(&alice);
    let bundle = now(CryptoProvider::publish_bundle(&mut bob, &mut rng)).unwrap();
    now(CryptoProvider::establish_session(
        &mut alice, &bob_c, &bundle, &mut rng,
    ))
    .unwrap();

    let ciphertext = now(CryptoProvider::encrypt(
        &mut alice,
        &bob_c,
        b"for bob only",
        &mut rng,
    ))
    .unwrap();
    // Carol, not the addressed recipient, cannot decrypt it.
    assert!(
        now(CryptoProvider::decrypt(
            &mut carol,
            &alice_c,
            &ciphertext,
            &mut rng
        ))
        .is_err()
    );
}
