//! Registration trust: how a directory registration is admitted, and the
//! two distinct attacks it must turn away.
//!
//! Admitting a registration takes two independent checks, one per layer:
//!
//! 1. **Proof of possession** (cryptographic, done here by the admitting
//!    server): the registrant signs a server-chosen challenge with the
//!    identity private key it is submitting, and the server verifies that
//!    signature against the *submitted* identity key. This proves the
//!    registrant actually holds the key it claims — you cannot register an
//!    identity you do not possess.
//! 2. **Trust on first use** (the directory, a crypto-free byte
//!    comparison): the first registration of an address binds it to an
//!    identity key; a later one must present the same key. This stops a
//!    bound address from being reassigned to someone else's identity.
//!
//! Each check stops an attack the other cannot. Possession alone would
//! let Mallory bind *her own* key to Bob's address (she can prove she
//! holds her key). Trust-on-first-use alone would let Mallory submit Bob's
//! identity key for a fresh address (no binding exists yet to compare
//! against). Both together admit only a registrant who holds the submitted
//! key and is not stepping on an existing binding.

use futures_util::FutureExt;
use rand::TryRngCore as _;
use tacenta_core::crypto::{CryptoProvider, DefaultProvider};
use tacenta_directory::{Directory, Registration};
use tacenta_relay::DeviceAddr;

fn now<T>(fut: impl std::future::Future<Output = T>) -> T {
    fut.now_or_never()
        .expect("in-memory protocol store future did not complete synchronously")
}

/// A server admitting a registration: prove possession of the submitted
/// identity key, then let the directory apply trust on first use.
enum Admission {
    /// Possession proven; the directory returned this outcome.
    Admitted(Registration),
    /// The signature did not verify against the submitted identity key —
    /// the registrant does not hold it. Never reaches the directory.
    PossessionFailed,
}

fn admit(
    directory: &mut Directory,
    device: &DeviceAddr,
    identity: Vec<u8>,
    bundle: Vec<u8>,
    challenge: &[u8],
    signature: &[u8],
) -> Admission {
    if !tacenta_core::crypto::verify_challenge(&identity, challenge, signature) {
        return Admission::PossessionFailed;
    }
    Admission::Admitted(directory.register(device, identity, bundle))
}

/// A party's material for a registration: its identity key bytes and a
/// freshly published prekey bundle, both as opaque bytes.
fn material(party: &mut DefaultProvider) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let bundle = now(CryptoProvider::publish_bundle(party, &mut rng)).unwrap();
    (CryptoProvider::identity_key(party), bundle)
}

#[test]
fn registration_trust_turns_away_both_attacks() {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let mut directory = Directory::new();

    let mut bob = DefaultProvider::generate("+bob", 1, &mut rng).unwrap();
    let mut mallory = DefaultProvider::generate("+mallory", 1, &mut rng).unwrap();
    let bob_addr = DeviceAddr::new("+bob", 1);

    // Bob registers his own address with his own key, proving possession.
    let (bob_identity, bob_bundle) = material(&mut bob);
    let challenge = b"server-nonce-1";
    let sig = bob.sign_challenge(challenge, &mut rng);
    assert!(matches!(
        admit(
            &mut directory,
            &bob_addr,
            bob_identity.clone(),
            bob_bundle,
            challenge,
            &sig,
        ),
        Admission::Admitted(Registration::Registered)
    ));

    // Attack 1 — hijack a bound address. Mallory proves possession of *her
    // own* key (so proof-of-possession passes) but aims it at Bob's
    // address. Trust on first use rejects it; Bob's binding is untouched.
    let (mallory_identity, mallory_bundle) = material(&mut mallory);
    let challenge = b"server-nonce-2";
    let sig = mallory.sign_challenge(challenge, &mut rng);
    assert!(matches!(
        admit(
            &mut directory,
            &bob_addr,
            mallory_identity,
            mallory_bundle,
            challenge,
            &sig,
        ),
        Admission::Admitted(Registration::Rejected)
    ));
    assert_eq!(directory.identity(&bob_addr), Some(&bob_identity[..]));

    // Attack 2 — impersonate an identity. Mallory submits *Bob's* identity
    // key for a fresh address she controls, but she cannot sign the
    // challenge with Bob's private key. Proof-of-possession rejects it
    // before the directory is ever consulted.
    let mallory_addr = DeviceAddr::new("+mallory", 2);
    let challenge = b"server-nonce-3";
    let sig = mallory.sign_challenge(challenge, &mut rng); // signed with Mallory's key
    let (_, some_bundle) = material(&mut mallory);
    assert!(matches!(
        admit(
            &mut directory,
            &mallory_addr,
            bob_identity.clone(), // but claims Bob's identity
            some_bundle,
            challenge,
            &sig,
        ),
        Admission::PossessionFailed
    ));
    assert_eq!(directory.identity(&mallory_addr), None);
}
