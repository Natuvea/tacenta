//! What the provider at this seam must do, written once against the trait.
//!
//! This is the behavioural conformance suite for the provider seam, in the only
//! form that can honestly be written: **behaviour, not bytes.**
//!
//! A provider is free to derive keys under its own labels and encode messages in
//! its own way; those are implementation choices, not part of the contract. A
//! byte-level comparison would assert something the seam never promised. What the
//! suite demands is that the same sequence of operations produces the same
//! plaintexts at the far end and fails in the same cases, which is what a caller
//! of this seam actually depends on.
//!
//! Written generically over the trait, so it is a definition of the seam's
//! contract that the provider either meets or does not.
//!
//! These functions panic on failure rather than returning a result, because
//! they are run from `#[test]` and a panic is what a test wants. Each carries
//! enough context in the message to say what failed and where.

use super::provider::{Address, CryptoProvider, Failure};
use rand::{CryptoRng, Rng};

/// Drive a future to completion.
///
/// Every store this seam has is in memory, so these futures are already
/// resolved and this only unwraps them. If a provider ever needs real I/O here,
/// this assumption fails loudly rather than hanging.
fn now<T>(fut: impl Future<Output = T>) -> T {
    use futures_util::FutureExt;
    fut.now_or_never()
        .expect("provider futures complete synchronously with in-memory stores")
}

/// Two parties, each having published a bundle, with `a` having opened a
/// session toward `b`. The starting point for most of what follows.
fn paired<P: CryptoProvider, R: Rng + CryptoRng>(csprng: &mut R) -> (P, P, Address, Address) {
    let mut a = P::generate("alice", 1, csprng).expect("generate alice");
    let mut b = P::generate("bob", 1, csprng).expect("generate bob");
    let (addr_a, addr_b) = (a.address(), b.address());

    let bundle_b = now(b.publish_bundle(csprng)).expect("bob publishes");
    now(a.establish_session(&addr_b, &bundle_b, csprng)).expect("alice establishes toward bob");

    (a, b, addr_a, addr_b)
}

/// A message encrypted for a peer decrypts, at that peer, to what was sent.
///
/// The first thing a provider has to do, and the first thing to check.
pub fn round_trip<P: CryptoProvider, R: Rng + CryptoRng>(csprng: &mut R) {
    let (mut a, mut b, addr_a, addr_b) = paired::<P, R>(csprng);

    let sent = b"the quick brown fox";
    let framed = now(a.encrypt(&addr_b, sent, csprng)).expect("alice encrypts");
    let got = now(b.decrypt(&addr_a, &framed, csprng)).expect("bob decrypts");

    assert_eq!(got, sent, "{}: round trip", P::NAME);
    assert_ne!(framed, sent, "{}: ciphertext is not the plaintext", P::NAME);
}

/// A conversation runs in both directions, not only the one that opened it.
///
/// Worth its own case: the responder's first send is where a provider has to
/// have taken the ratchet step the initiator's message implied, and getting it
/// wrong still passes a one-way test.
pub fn bidirectional<P: CryptoProvider, R: Rng + CryptoRng>(csprng: &mut R) {
    let (mut a, mut b, addr_a, addr_b) = paired::<P, R>(csprng);

    let first = now(a.encrypt(&addr_b, b"from alice", csprng)).expect("alice encrypts");
    let got = now(b.decrypt(&addr_a, &first, csprng)).expect("bob decrypts");
    assert_eq!(got, b"from alice", "{}: first leg", P::NAME);

    let reply = now(b.encrypt(&addr_a, b"from bob", csprng)).expect("bob encrypts");
    let got = now(a.decrypt(&addr_b, &reply, csprng)).expect("alice decrypts");
    assert_eq!(got, b"from bob", "{}: reply leg", P::NAME);
}

/// Many messages in order all arrive, and each is distinct.
pub fn in_order<P: CryptoProvider, R: Rng + CryptoRng>(csprng: &mut R) {
    let (mut a, mut b, addr_a, addr_b) = paired::<P, R>(csprng);

    let mut ciphertexts = Vec::new();
    for i in 0u8..8 {
        let msg = [b'm', i];
        ciphertexts.push((msg, now(a.encrypt(&addr_b, &msg, csprng)).expect("encrypt")));
    }

    for (msg, framed) in &ciphertexts {
        let got = now(b.decrypt(&addr_a, framed, csprng)).expect("decrypt in order");
        assert_eq!(got, msg, "{}: in-order message", P::NAME);
    }

    // Distinct ciphertexts for distinct messages, which a broken ratchet that
    // reused a key would not give.
    let bodies: std::collections::HashSet<_> = ciphertexts.iter().map(|(_, c)| c).collect();
    assert_eq!(bodies.len(), 8, "{}: every ciphertext differs", P::NAME);
}

/// Messages delivered out of order still decrypt, which is what the skipped-key
/// store exists for.
pub fn out_of_order<P: CryptoProvider, R: Rng + CryptoRng>(csprng: &mut R) {
    let (mut a, mut b, addr_a, addr_b) = paired::<P, R>(csprng);

    let one = now(a.encrypt(&addr_b, b"first", csprng)).expect("encrypt first");
    let two = now(a.encrypt(&addr_b, b"second", csprng)).expect("encrypt second");
    let three = now(a.encrypt(&addr_b, b"third", csprng)).expect("encrypt third");

    // Third, then first, then second.
    assert_eq!(
        now(b.decrypt(&addr_a, &three, csprng)).expect("decrypt third"),
        b"third",
        "{}: latest first",
        P::NAME
    );
    assert_eq!(
        now(b.decrypt(&addr_a, &one, csprng)).expect("decrypt first"),
        b"first",
        "{}: earliest from the store",
        P::NAME
    );
    assert_eq!(
        now(b.decrypt(&addr_a, &two, csprng)).expect("decrypt second"),
        b"second",
        "{}: middle from the store",
        P::NAME
    );
}

/// Tampering with a ciphertext never changes the plaintext it delivers.
///
/// Every byte position is flipped, not a sampled few: a provider that
/// authenticated only part of its message would pass a spot check.
///
/// The property is stated carefully. It does not assert that *every* flip
/// must cause a failure, because the provider does not do that: a message
/// carries framing bytes outside the authenticator -- the transport tag and
/// the version -- and flipping one of those leaves a message that still
/// decrypts, to exactly what was sent. That is not an integrity failure. An
/// attacker who flips an inert byte has changed nothing a recipient can
/// observe.
///
/// So the property is that tampering either fails or is inert, and never yields
/// a *different* plaintext. That is what a caller depends on, and it is what
/// the provider can be held to. The count of inert positions is asserted to
/// be small, because a provider where most of the message was inert would be
/// meeting the letter of this and not its point.
pub fn tampering_is_rejected<P: CryptoProvider, R: Rng + CryptoRng>(csprng: &mut R) {
    let (mut a, mut b, addr_a, addr_b) = paired::<P, R>(csprng);
    let framed = now(a.encrypt(&addr_b, b"authentic", csprng)).expect("encrypt");
    let mut inert: Vec<usize> = Vec::new();
    let mut rejected = 0usize;

    for i in 0..framed.len() {
        let mut bad = framed.clone();
        bad[i] ^= 0x01;
        if bad == framed {
            continue;
        }
        match now(b.decrypt(&addr_a, &bad, csprng)) {
            // Inert: the byte is outside what the authenticator covers, so the
            // message still decrypts -- to exactly what was sent. That is not a
            // failure of integrity, and the assertion is that it produced the
            // *same* plaintext, not that it failed.
            Ok(plain) => {
                assert_eq!(
                    plain,
                    b"authentic",
                    "{}: flipping byte {i} changed the plaintext",
                    P::NAME
                );
                inert.push(i);
            }
            Err(_) => rejected += 1,
        }
    }

    assert!(
        rejected > 0,
        "{}: no byte flip was rejected at all",
        P::NAME
    );
    assert!(
        inert.len() * 8 < framed.len(),
        "{}: {} of {} byte positions are outside the authenticator ({inert:?}); \
         that is more framing than a message this size should have",
        P::NAME,
        inert.len(),
        framed.len()
    );
}

/// A message that has already been decrypted is not accepted a second time.
///
/// The stored key for a message is consumed when it is used, so a replay finds
/// nothing. This is the property that keeps an attacker who records a message
/// from having it delivered twice.
pub fn replay_is_rejected<P: CryptoProvider, R: Rng + CryptoRng>(csprng: &mut R) {
    let (mut a, mut b, addr_a, addr_b) = paired::<P, R>(csprng);
    let framed = now(a.encrypt(&addr_b, b"once", csprng)).expect("encrypt");

    assert_eq!(
        now(b.decrypt(&addr_a, &framed, csprng)).expect("first delivery"),
        b"once",
        "{}: first delivery",
        P::NAME
    );
    let err = now(b.decrypt(&addr_a, &framed, csprng))
        .err()
        .unwrap_or_else(|| panic!("{}: the same ciphertext was accepted twice", P::NAME));
    assert_eq!(
        P::classify(&err),
        Failure::Undecryptable,
        "{}: a replay must fail as undecryptable, not in some other way",
        P::NAME
    );
}

/// An exported identity restores to the same party.
///
/// The identity key is what a peer trusts, so it has to survive a restart
/// unchanged. Sessions are not expected to: this checks the identity only, and
/// the restored party opens a fresh session.
pub fn identity_survives_export<P: CryptoProvider, R: Rng + CryptoRng>(csprng: &mut R) {
    let a = P::generate("alice", 1, csprng).expect("generate");
    let exported = a.export_identity();
    let restored = P::from_identity("alice", 1, &exported).expect("restore");

    assert_eq!(
        a.identity_key(),
        restored.identity_key(),
        "{}: identity key survives export",
        P::NAME
    );
    assert_eq!(a.address(), restored.address(), "{}: address", P::NAME);
}

/// A challenge signature verifies against the signer's published identity, and
/// nothing else does.
///
/// This is the property the server depends on, and it is the only one in this
/// suite that both sides of a deployment must satisfy *together*: a client
/// signing under one provider and a server verifying under another would
/// reject every connection. It is checked here because the seam's static half
/// is as much a part of the contract as the session half.
pub fn challenge_signature_verifies<P: CryptoProvider, R: Rng + CryptoRng>(csprng: &mut R) {
    let a = P::generate("alice", 1, csprng).expect("generate alice");
    let b = P::generate("bob", 1, csprng).expect("generate bob");

    let challenge = b"a server-issued challenge";
    let sig = a.sign_challenge(challenge, csprng);

    assert!(
        P::verify_challenge(&a.identity_key(), challenge, &sig),
        "{}: a signature did not verify against its own identity",
        P::NAME
    );
    assert!(
        !P::verify_challenge(&b.identity_key(), challenge, &sig),
        "{}: a signature verified against the wrong identity",
        P::NAME
    );
    assert!(
        !P::verify_challenge(&a.identity_key(), b"a different challenge", &sig),
        "{}: a signature verified over the wrong challenge",
        P::NAME
    );

    let mut tampered = sig.clone();
    tampered[0] ^= 0x01;
    assert!(
        !P::verify_challenge(&a.identity_key(), challenge, &tampered),
        "{}: a tampered signature verified",
        P::NAME
    );
    assert!(
        !P::verify_challenge(&[], challenge, &sig),
        "{}: an empty identity verified a signature",
        P::NAME
    );
}

/// A bundle that has been corrupted is rejected rather than used.
pub fn corrupt_bundle_is_rejected<P: CryptoProvider, R: Rng + CryptoRng>(csprng: &mut R) {
    let mut a = P::generate("alice", 1, csprng).expect("generate alice");
    let mut b = P::generate("bob", 1, csprng).expect("generate bob");
    let addr_b = b.address();

    let bundle = now(b.publish_bundle(csprng)).expect("publish");

    // Truncation, which no encoding should accept.
    let truncated = &bundle[..bundle.len() / 2];
    let err = now(a.establish_session(&addr_b, truncated, csprng))
        .err()
        .unwrap_or_else(|| panic!("{}: a truncated bundle was accepted", P::NAME));
    assert_eq!(
        P::classify(&err),
        Failure::BadBundle,
        "{}: a truncated bundle must be rejected as a bad bundle",
        P::NAME
    );

    // And an empty one.
    assert!(
        now(a.establish_session(&addr_b, &[], csprng)).is_err(),
        "{}: an empty bundle was accepted",
        P::NAME
    );
}

/// Everything above, so a provider can be checked with one call.
///
/// Ordered cheapest first, so a provider that is badly wrong fails on the
/// simplest case rather than somewhere confusing.
pub fn full_suite<P: CryptoProvider, R: Rng + CryptoRng>(csprng: &mut R) {
    round_trip::<P, R>(csprng);
    bidirectional::<P, R>(csprng);
    in_order::<P, R>(csprng);
    out_of_order::<P, R>(csprng);
    identity_survives_export::<P, R>(csprng);
    challenge_signature_verifies::<P, R>(csprng);
    corrupt_bundle_is_rejected::<P, R>(csprng);
    replay_is_rejected::<P, R>(csprng);
    tampering_is_rejected::<P, R>(csprng);
}
