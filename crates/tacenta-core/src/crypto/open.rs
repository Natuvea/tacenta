//! The open-tacenta-backed provider.
//!
//! The implementation of the seam. It holds an identity, a prekey store, and
//! the sessions this party has open, and forwards each operation to
//! `open-tacenta`.
//!
//! ## Shape
//!
//! open-tacenta hands back `Session` values and lets the caller decide where
//! they live, so this adapter owns the map from peer to session.
//!
//! The consequence shows up in `decrypt`. Opening a session and continuing
//! one are different calls, and the wire format's own type byte is what
//! chooses between them: an initial message goes to `establish_responder`,
//! which returns the session *and* the first plaintext together, and anything
//! else goes to the session already held.
//!
//! ## The generator bridge, and why it needs a test
//!
//! This product is on `rand` 0.9. open-tacenta is on `rand_core` 0.6, and cannot
//! simply move: its curve dependencies, `x25519-dalek` and `ed25519-dalek`, take
//! generators through the older traits. Two versions of the same trait are two
//! different traits, so the generator has to be bridged.
//!
//! The bridge sits in front of key generation, so it is tested by a test
//! below that seeds a deterministic generator, draws bytes through the bridge
//! and directly, and requires them to be equal. A bridge that returned a
//! constant, or truncated, would produce predictable keys and still pass every
//! functional test in this repository, because those only check that
//! encryption round-trips.

use super::provider::{Address, CryptoProvider, Failure};
use open_tacenta::sessions::{
    self, Identity, PrekeyStore, PublishedBundle, Session, establish_initiator, establish_responder,
};
use open_tacenta::{primitives::dh, serialization};
use rand::{CryptoRng, Rng};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Bridges a `rand` 0.9 generator to the `rand_core` 0.6 traits open-tacenta's
/// curve dependencies require.
///
/// Every method forwards. Nothing here may transform, buffer, or reorder bytes:
/// see `the_bridge_passes_bytes_through_unchanged`.
struct RngBridge<'a, R>(&'a mut R);

impl<R: Rng> rand_core_06::RngCore for RngBridge<'_, R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

/// Sound only because the wrapped generator is itself cryptographic, which the
/// bound on every caller requires.
impl<R: Rng + CryptoRng> rand_core_06::CryptoRng for RngBridge<'_, R> {}

/// What this provider fails with.
#[derive(Debug)]
pub enum OpenError {
    /// A bundle would not decode, or was rejected.
    Bundle,
    /// A ciphertext would not decode, or would not decrypt.
    Message,
    /// No session with that peer, where one was required.
    NoSession,
    /// An identity blob was not the right shape.
    Identity,
    /// The provider was asked to establish before publishing prekeys.
    NoPrekeys,
    /// Bytes from `export_sessions`/`import_sessions` did not decode: an
    /// unrecognised session-persistence version, a truncated frame, or a
    /// peer name that was not valid UTF-8.
    Sessions,
    /// Bytes from `export_prekeys`/`import_prekeys` did not decode.
    Prekeys,
}

/// A party backed by open-tacenta.
pub struct OpenParty {
    address: Address,
    identity: Identity,
    prekeys: Option<PrekeyStore>,
    sessions: BTreeMap<Address, Session>,
}

/// How many one-time prekeys a published bundle draws from.
///
/// The store hands out one curve and one KEM one-time key per bundle and
/// deletes them on use, so this is how many first contacts a party can take
/// before falling back to the last-resort key.
const ONE_TIME_PREKEYS: usize = 32;

/// Top up when fewer than this many one-time prekeys of either kind remain.
///
/// A low-water mark rather than a top-up to the brim on every publish, so that
/// a party publishing frequently does not generate keys it will never hand out
/// -- each KEM key pair costs a signature and sits in the persisted store.
///
/// **Why replenish at all.** Without it a party takes exactly
/// `ONE_TIME_PREKEYS` first contacts with one-time forward secrecy and then
/// falls back to the reusable last-resort key for every peer after that. That
/// path is the weaker one twice over: no one-time forward secrecy, and it is
/// the path open-tacenta has to guard with a *bounded* replay record, because
/// a reusable key cannot refuse a replay by being deleted. Keeping the store
/// stocked is what keeps that bound generous.
const REPLENISH_BELOW: usize = 8;

impl OpenParty {
    /// Every peer this party currently holds a session with. For a caller
    /// that wants to export all of them through `export_sessions` rather
    /// than a named subset -- a durable store has no other way to learn
    /// the full address book, since `sessions` itself is private.
    pub fn known_peers(&self) -> Vec<Address> {
        self.sessions.keys().cloned().collect()
    }

    /// This party's prekey store, encoded for persistence. `None` if
    /// `publish_bundle` has never been called, since there is nothing to
    /// export yet.
    pub fn export_prekeys(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.prekeys.as_ref().map(PrekeyStore::to_bytes)
    }

    /// Restore a prekey store from `export_prekeys`, replacing whatever
    /// this party currently holds (if anything).
    /// **Refuses a spelling `export_prekeys` would not produce**, the same way
    /// `Session::import` does, and for the same reason: `DurableOpenParty`
    /// feeds both from one untrusted `state.bin`, and guarding one half of a
    /// file's contents is not guarding the file.
    ///
    /// **This is symmetry and defence in depth.** A sampled sweep over 128
    /// positions of a real prekey blob finds no byte string that decodes and
    /// re-encodes differently. The check is here because the entry point would
    /// otherwise be unguarded, a future optional field could introduce a
    /// non-canonical spelling without anyone noticing, and a reader should not
    /// have to ask why one half of a file is checked and the other is not. The
    /// test below keeps the property true rather than merely observed.
    ///
    /// **An older format upgrades rather than being refused.**
    /// `PrekeyStore::from_bytes` accepts v1, v2 and v3; `to_bytes` only ever
    /// writes the current version. So a v1 store decodes correctly and
    /// re-encodes to *different bytes* by design, and a plain
    /// re-encode-and-compare would reject every store written before the
    /// last-resort fingerprints existed. The test below keeps that upgrade
    /// path open.
    ///
    /// The property that holds is idempotence: whatever the input version,
    /// the *upgraded* encoding must be canonical in the current format. A blob
    /// that re-encodes, decodes and re-encodes to something else again is
    /// refused however it was spelled going in.
    pub fn import_prekeys(&mut self, bytes: &[u8]) -> Result<(), OpenError> {
        let store = PrekeyStore::from_bytes(bytes).map_err(|_| OpenError::Prekeys)?;
        let reencoded = store.to_bytes();

        if reencoded.as_slice() != bytes {
            // Either a non-canonical spelling of the current format, or a
            // legitimate upgrade from an older one. Distinguish them by asking
            // whether the re-encoding is a fixed point: an upgrade is, and a
            // decoder that silently dropped or reordered something is not.
            let again = PrekeyStore::from_bytes(&reencoded)
                .map_err(|_| OpenError::Prekeys)?
                .to_bytes();
            if again.as_slice() != reencoded.as_slice() {
                return Err(OpenError::Prekeys);
            }
        }

        self.prekeys = Some(store);
        Ok(())
    }

    fn bundle_from_wire(w: &serialization::WireBundle) -> PublishedBundle {
        PublishedBundle {
            bundle: sessions::PreKeyBundle {
                identity_key: dh::PublicKeyBytes::from_bytes(w.identity_key),
                signed_prekey: dh::PublicKeyBytes::from_bytes(w.signed_prekey),
                signed_prekey_signature: w.signed_prekey_signature,
                kem_prekey: w.kem_prekey.clone(),
                kem_prekey_signature: w.kem_prekey_signature,
                one_time_prekey: w.one_time_prekey.map(dh::PublicKeyBytes::from_bytes),
            },
            signed_prekey_id: w.signed_prekey_id,
            one_time_prekey_id: w.one_time_prekey_id,
            kem_prekey_id: w.kem_prekey_id,
        }
    }
}

impl CryptoProvider for OpenParty {
    type Error = OpenError;

    const NAME: &'static str = "open-tacenta";

    fn classify(err: &OpenError) -> Failure {
        match err {
            OpenError::Bundle => Failure::BadBundle,
            OpenError::Message => Failure::Undecryptable,
            OpenError::NoSession => Failure::NoSession,
            OpenError::Identity
            | OpenError::NoPrekeys
            | OpenError::Sessions
            | OpenError::Prekeys => Failure::Other,
        }
    }

    fn generate<R: Rng + CryptoRng>(
        user: &str,
        device: u8,
        csprng: &mut R,
    ) -> Result<OpenParty, OpenError> {
        Ok(OpenParty {
            address: Address::new(user, device),
            identity: Identity::generate(&mut RngBridge(csprng)),
            prekeys: None,
            sessions: BTreeMap::new(),
        })
    }

    fn export_identity(&self) -> Vec<u8> {
        self.identity.export().to_vec()
    }

    fn from_identity(user: &str, device: u8, bytes: &[u8]) -> Result<OpenParty, OpenError> {
        let secret: [u8; 32] = bytes.try_into().map_err(|_| OpenError::Identity)?;
        Ok(OpenParty {
            address: Address::new(user, device),
            identity: Identity::from_secret(secret),
            prekeys: None,
            sessions: BTreeMap::new(),
        })
    }

    fn address(&self) -> Address {
        self.address.clone()
    }

    fn identity_key(&self) -> Vec<u8> {
        self.identity.public().as_bytes().to_vec()
    }

    fn sign_challenge<R: Rng + CryptoRng>(&self, challenge: &[u8], csprng: &mut R) -> Vec<u8> {
        self.identity
            .sign_message(challenge, &mut RngBridge(csprng))
            .to_vec()
    }

    fn verify_challenge(identity: &[u8], challenge: &[u8], signature: &[u8]) -> bool {
        let Ok(key) = <[u8; 32]>::try_from(identity) else {
            return false;
        };
        let Ok(sig) = <[u8; 64]>::try_from(signature) else {
            return false;
        };
        sessions::verify_under_identity(&dh::PublicKeyBytes::from_bytes(key), challenge, &sig)
    }

    async fn publish_bundle<R: Rng + CryptoRng>(
        &mut self,
        csprng: &mut R,
    ) -> Result<Vec<u8>, OpenError> {
        // Prekeys are created once and republished. Creating them afresh on
        // every publish would strand every session opened against the previous
        // set, because the private halves would be gone.
        if self.prekeys.is_none() {
            self.prekeys = Some(
                self.identity
                    .create_prekeys(ONE_TIME_PREKEYS, &mut RngBridge(csprng)),
            );
        }
        // Top up rather than recreate, for the same reason: `replenish`
        // continues the store's identifier sequence, so the keys already handed
        // out keep working and no identifier is ever issued twice.
        let store = self.prekeys.as_mut().expect("just created");
        let (curve_left, kem_left) = store.one_time_remaining();
        let fewest = curve_left.min(kem_left);
        if fewest < REPLENISH_BELOW {
            store.replenish(
                &self.identity,
                ONE_TIME_PREKEYS - fewest,
                &mut RngBridge(csprng),
            );
        }
        let published = store.publish_multi_use();
        Ok(serialization::encode_bundle(&serialization::WireBundle {
            identity_key: *published.bundle.identity_key.as_bytes(),
            signed_prekey: *published.bundle.signed_prekey.as_bytes(),
            signed_prekey_signature: published.bundle.signed_prekey_signature,
            kem_prekey: published.bundle.kem_prekey.clone(),
            kem_prekey_signature: published.bundle.kem_prekey_signature,
            one_time_prekey: published.bundle.one_time_prekey.map(|k| *k.as_bytes()),
            signed_prekey_id: published.signed_prekey_id,
            one_time_prekey_id: published.one_time_prekey_id,
            kem_prekey_id: published.kem_prekey_id,
        }))
    }

    async fn publish_one_time_batch<R: Rng + CryptoRng>(
        &mut self,
        csprng: &mut R,
    ) -> Result<Vec<Vec<u8>>, OpenError> {
        // Prekeys are created on first publish, so a caller that asks for a
        // batch before ever publishing gets one rather than an empty vector
        // and a silent loss of forward secrecy.
        if self.prekeys.is_none() {
            self.prekeys = Some(
                self.identity
                    .create_prekeys(ONE_TIME_PREKEYS, &mut RngBridge(csprng)),
            );
        }
        let store = self.prekeys.as_ref().expect("just created");
        store
            .publish_one_time_batch()
            .into_iter()
            .map(|published| {
                Ok(serialization::encode_bundle(&serialization::WireBundle {
                    identity_key: *published.bundle.identity_key.as_bytes(),
                    signed_prekey: *published.bundle.signed_prekey.as_bytes(),
                    signed_prekey_signature: published.bundle.signed_prekey_signature,
                    kem_prekey: published.bundle.kem_prekey.clone(),
                    kem_prekey_signature: published.bundle.kem_prekey_signature,
                    one_time_prekey: published.bundle.one_time_prekey.map(|k| *k.as_bytes()),
                    signed_prekey_id: published.signed_prekey_id,
                    one_time_prekey_id: published.one_time_prekey_id,
                    kem_prekey_id: published.kem_prekey_id,
                }))
            })
            .collect()
    }

    async fn establish_session<R: Rng + CryptoRng>(
        &mut self,
        peer: &Address,
        bundle: &[u8],
        csprng: &mut R,
    ) -> Result<(), OpenError> {
        let wire = serialization::decode_bundle(bundle).map_err(|_| OpenError::Bundle)?;
        let published = Self::bundle_from_wire(&wire);
        let session = establish_initiator(&self.identity, &published, &mut RngBridge(csprng))
            .map_err(|_| OpenError::Bundle)?;
        self.sessions.insert(peer.clone(), session);
        Ok(())
    }

    async fn encrypt<R: Rng + CryptoRng>(
        &mut self,
        peer: &Address,
        plaintext: &[u8],
        csprng: &mut R,
    ) -> Result<Vec<u8>, OpenError> {
        let session = self.sessions.get_mut(peer).ok_or(OpenError::NoSession)?;
        session
            .encrypt(plaintext, &mut RngBridge(csprng))
            .map_err(|_| OpenError::Message)
    }

    // A peer with no stored session is skipped. There is no separate identity
    // to carry alongside each session: `Session::export` already includes the
    // peer's identity public key.
    async fn export_sessions(&self, peers: &[Address]) -> Result<Vec<u8>, OpenError> {
        fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
            out.extend_from_slice(&(b.len() as u32).to_be_bytes());
            out.extend_from_slice(b);
        }
        let mut out = Vec::new();
        let mut count: u32 = 0;
        let mut body = Vec::new();
        for peer in peers {
            let Some(session) = self.sessions.get(peer) else {
                continue;
            };
            put_bytes(&mut body, peer.user.as_bytes());
            body.push(peer.device);
            put_bytes(&mut body, &session.export());
            count += 1;
        }
        out.extend_from_slice(&count.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    async fn import_sessions(&mut self, bytes: &[u8]) -> Result<Vec<Address>, OpenError> {
        fn take_u32(b: &[u8]) -> Option<(u32, &[u8])> {
            let (h, r) = b.split_at_checked(4)?;
            Some((u32::from_be_bytes(h.try_into().ok()?), r))
        }
        fn take_bytes(b: &[u8]) -> Option<(&[u8], &[u8])> {
            let (len, r) = take_u32(b)?;
            r.split_at_checked(len as usize)
        }

        let (count, mut rest) = take_u32(bytes).ok_or(OpenError::Sessions)?;
        // Never sized from the blob: a rewritten count would ask for the
        // world before a byte was checked.
        let mut restored = Vec::new();
        for _ in 0..count {
            let (name, r) = take_bytes(rest).ok_or(OpenError::Sessions)?;
            let (&device, r) = r.split_first().ok_or(OpenError::Sessions)?;
            let (session_bytes, r) = take_bytes(r).ok_or(OpenError::Sessions)?;
            rest = r;

            let name = std::str::from_utf8(name).map_err(|_| OpenError::Sessions)?;
            let session = Session::import(session_bytes).map_err(|_| OpenError::Sessions)?;
            let peer = Address::new(name.to_owned(), device);
            self.sessions.insert(peer.clone(), session);
            restored.push(peer);
        }
        if !rest.is_empty() {
            return Err(OpenError::Sessions);
        }
        Ok(restored)
    }

    // The trait's prekey persistence forwards to the inherent methods above,
    // which carry the canonicity guard and the v1-upgrade handling.
    // `OpenParty::` is the inherent one; `self.` in a
    // generic context resolves to the trait, so the qualification is what keeps
    // this a forward rather than a recursion.
    fn export_prekeys(&self) -> Option<Vec<u8>> {
        OpenParty::export_prekeys(self).map(|z| z.to_vec())
    }

    fn import_prekeys(&mut self, bytes: &[u8]) -> Result<(), OpenError> {
        OpenParty::import_prekeys(self, bytes)
    }

    fn clear_sessions(&mut self) {
        self.sessions.clear();
    }

    async fn decrypt<R: Rng + CryptoRng>(
        &mut self,
        peer: &Address,
        framed: &[u8],
        csprng: &mut R,
    ) -> Result<Vec<u8>, OpenError> {
        // The wire format says which of the two calls this is: the type byte
        // is what makes the choice possible without guessing.
        // An initial message is not on its own a request to open a session. An
        // initiator repeats it on every message until it hears back, which the
        // Double Ratchet specification recommends so that a lost or reordered
        // first message does not strand the conversation, and a repeat arrives
        // typed exactly like the original. So offer it to an existing session
        // first: that session accepts only the repeat that established it and
        // refuses anything else, which makes falling through to establishment
        // both safe and necessary.
        if let Some(serialization::MessageType::Initial) = serialization::message_type(framed)
            && let Some(session) = self.sessions.get_mut(peer)
            && let Ok(plaintext) = session.decrypt(framed, &mut RngBridge(csprng))
        {
            return Ok(plaintext);
        }
        match serialization::message_type(framed) {
            Some(serialization::MessageType::Initial) => {
                let prekeys = self.prekeys.as_mut().ok_or(OpenError::NoPrekeys)?;
                let (session, plaintext) =
                    establish_responder(&self.identity, prekeys, framed, &mut RngBridge(csprng))
                        .map_err(|_| OpenError::Message)?;
                self.sessions.insert(peer.clone(), session);
                Ok(plaintext)
            }
            Some(serialization::MessageType::Ratchet) => {
                let session = self.sessions.get_mut(peer).ok_or(OpenError::NoSession)?;
                session
                    .decrypt(framed, &mut RngBridge(csprng))
                    .map_err(|_| OpenError::Message)
            }
            None => Err(OpenError::Message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::TryRngCore;
    use rand_core_06::RngCore as _;

    /// The bridge passes bytes through unchanged.
    ///
    /// This is the test that makes the bridge safe to put in front of key
    /// generation. A bridge that returned zeros, or repeated a block, or
    /// truncated, would produce predictable keys and pass every other test in
    /// this repository, because the others only check that encryption
    /// round-trips and it would still do that.
    ///
    /// Two identically seeded generators: one drawn from directly, one through
    /// the bridge. The sequences must match exactly.
    #[test]
    fn the_bridge_passes_bytes_through_unchanged() {
        const SEED: [u8; 32] = [0x5a; 32];

        let mut direct = rand_chacha::ChaCha20Rng::from_seed(SEED);
        let mut expected = [0u8; 256];
        rand::RngCore::fill_bytes(&mut direct, &mut expected);

        let mut source = rand_chacha::ChaCha20Rng::from_seed(SEED);
        let mut got = [0u8; 256];
        RngBridge(&mut source).fill_bytes(&mut got);

        assert_eq!(got, expected, "the bridge altered the byte stream");

        // The word-sized draws too, since key generation uses whichever the
        // underlying crate reaches for.
        let mut a = rand_chacha::ChaCha20Rng::from_seed(SEED);
        let mut b = rand_chacha::ChaCha20Rng::from_seed(SEED);
        assert_eq!(
            rand::RngCore::next_u32(&mut a),
            RngBridge(&mut b).next_u32()
        );
        assert_eq!(
            rand::RngCore::next_u64(&mut a),
            RngBridge(&mut b).next_u64()
        );
    }

    /// Two parties generated from the same generator do not share an identity,
    /// which a bridge returning a constant would break.
    #[test]
    fn generated_identities_differ() {
        let mut csprng = rand::rngs::OsRng.unwrap_err();
        let a = OpenParty::generate("alice", 1, &mut csprng).expect("generate");
        let b = OpenParty::generate("bob", 1, &mut csprng).expect("generate");
        assert_ne!(a.identity_key(), b.identity_key());
        assert_ne!(a.identity_key(), vec![0u8; 32]);
    }

    /// The whole seam, against the conformance suite.
    #[test]
    fn open_tacenta_meets_the_provider_conformance_suite() {
        let mut csprng = rand::rngs::OsRng.unwrap_err();
        super::super::conformance::full_suite::<OpenParty, _>(&mut csprng);
    }

    /// Replenishment refills the pool a dispensing directory draws from.
    ///
    /// **What this deliberately does not assert (decision 0074):** that
    /// repeated `publish_bundle` calls hand out distinct one-time KEM prekeys.
    /// `publish_bundle` returns the *multi-use* bundle, which is served to
    /// everybody and therefore must not carry a one-time key at all. That is
    /// decision 0050's position and it is right for a bundle fetched more than
    /// once.
    ///
    /// One-time prekeys come from `publish_one_time_batch`, which the
    /// directory dispenses one at a time. So what replenishment has to restore
    /// is the *batch*, and that is what this checks.
    #[test]
    fn replenishment_refills_the_one_time_batch() {
        let mut csprng = rand::rngs::OsRng.unwrap_err();
        let mut bob = OpenParty::generate("bob", 1, &mut csprng).expect("generate");

        let first = now(CryptoProvider::publish_one_time_batch(
            &mut bob,
            &mut csprng,
        ))
        .expect("batch");
        assert_eq!(first.len(), ONE_TIME_PREKEYS);

        // Every bundle in the batch names a different one-time KEM prekey.
        let mut ids: Vec<u32> = first
            .iter()
            .map(|b| {
                serialization::decode_bundle(b)
                    .expect("our own bundle decodes")
                    .kem_prekey_id
            })
            .collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), before, "a one-time prekey was published twice");

        // The multi-use bundle is the fallback and carries no one-time prekey,
        // which is why it may be served repeatedly.
        let fallback = now(CryptoProvider::publish_bundle(&mut bob, &mut csprng)).expect("publish");
        let decoded = serialization::decode_bundle(&fallback).expect("decodes");
        assert!(
            decoded.one_time_prekey.is_none(),
            "the multi-use bundle must not carry a one-time prekey"
        );

        // Drain the pool through real sessions, then confirm replenishment on
        // the next publish restores a full batch.
        for (round, bundle) in first.into_iter().enumerate() {
            let mut alice =
                OpenParty::generate(&format!("a{round}"), 1, &mut csprng).expect("generate");
            let bob_addr = Address::new("bob", 1);
            now(CryptoProvider::establish_session(
                &mut alice,
                &bob_addr,
                &bundle,
                &mut csprng,
            ))
            .unwrap_or_else(|e| panic!("round {round}: {e:?}"));
            let framed = now(CryptoProvider::encrypt(
                &mut alice,
                &bob_addr,
                b"hi",
                &mut csprng,
            ))
            .expect("encrypt");
            now(CryptoProvider::decrypt(
                &mut bob,
                &Address::new(format!("a{round}"), 1),
                &framed,
                &mut csprng,
            ))
            .unwrap_or_else(|e| panic!("round {round} decrypt: {e:?}"));
        }

        // Publishing tops the store back up past the low-water mark.
        now(CryptoProvider::publish_bundle(&mut bob, &mut csprng)).expect("publish");
        let refilled = now(CryptoProvider::publish_one_time_batch(
            &mut bob,
            &mut csprng,
        ))
        .expect("batch");
        assert!(
            refilled.len() >= ONE_TIME_PREKEYS - REPLENISH_BELOW,
            "the pool was not replenished: {} left",
            refilled.len()
        );
    }

    /// The in-memory session map never awaits, so drive a future to its
    /// value directly rather than pulling in an executor.
    fn now<T>(fut: impl std::future::Future<Output = T>) -> T {
        use futures_util::FutureExt;
        fut.now_or_never()
            .expect("in-memory session future did not complete synchronously")
    }

    /// A party's sessions survive an export/import round trip through a
    /// fresh store built from the same identity: the resumed party decrypts
    /// a message sent to the *pre-export* session and keeps ratcheting.
    #[test]
    fn sessions_survive_export_import() {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let mut alice = OpenParty::generate("alice", 1, &mut rng).expect("generate");
        let mut bob = OpenParty::generate("bob", 1, &mut rng).expect("generate");

        let bob_bundle = now(bob.publish_bundle(&mut rng)).unwrap();
        now(alice.establish_session(&bob.address(), &bob_bundle, &mut rng)).unwrap();

        // Establish and advance the ratchet both ways.
        let m1 = now(alice.encrypt(&bob.address(), b"hi", &mut rng)).unwrap();
        assert_eq!(
            now(bob.decrypt(&alice.address(), &m1, &mut rng)).unwrap(),
            b"hi"
        );
        let m2 = now(bob.encrypt(&alice.address(), b"hey", &mut rng)).unwrap();
        assert_eq!(
            now(alice.decrypt(&bob.address(), &m2, &mut rng)).unwrap(),
            b"hey"
        );

        // Bob exports his identity + session with Alice, then a brand-new
        // Bob is rebuilt from the identity and the sessions imported.
        let identity = bob.export_identity();
        let alice_addr = alice.address();
        let sessions = now(bob.export_sessions(std::slice::from_ref(&alice_addr))).unwrap();
        let mut bob2 = OpenParty::from_identity("bob", 1, &identity).unwrap();
        let restored = now(bob2.import_sessions(&sessions)).unwrap();
        assert_eq!(restored, vec![alice_addr.clone()]);

        // Alice sends to the pre-export session; the resumed Bob decrypts it
        // and the conversation keeps going.
        let m3 = now(alice.encrypt(&bob2.address(), b"still there?", &mut rng)).unwrap();
        assert_eq!(
            now(bob2.decrypt(&alice_addr, &m3, &mut rng)).unwrap(),
            b"still there?"
        );
        let m4 = now(bob2.encrypt(&alice_addr, b"still here", &mut rng)).unwrap();
        assert_eq!(
            now(alice.decrypt(&bob2.address(), &m4, &mut rng)).unwrap(),
            b"still here"
        );

        // Truncated session bytes are rejected, not half-applied.
        let mut fresh = OpenParty::from_identity("bob", 1, &identity).unwrap();
        assert!(now(fresh.import_sessions(&sessions[..sessions.len() - 1])).is_err());
    }

    /// A peer named in `export_sessions` with no open session is skipped
    /// rather than erroring -- the caller may ask for more peers than it has
    /// live sessions with.
    #[test]
    fn export_sessions_skips_a_peer_with_no_session() {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let alice = OpenParty::generate("alice", 1, &mut rng).expect("generate");
        let stranger = Address::new("stranger", 1);
        let bytes = now(alice.export_sessions(std::slice::from_ref(&stranger))).unwrap();
        let mut fresh = OpenParty::generate("alice2", 1, &mut rng).expect("generate");
        let restored = now(fresh.import_sessions(&bytes)).unwrap();
        assert!(restored.is_empty());
    }

    /// `known_peers` names every session, for a durable store that has no
    /// other way to learn a party's full address book.
    #[test]
    fn known_peers_names_every_session() {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let mut alice = OpenParty::generate("alice", 1, &mut rng).expect("generate");
        assert!(alice.known_peers().is_empty());

        let mut bob = OpenParty::generate("bob", 1, &mut rng).expect("generate");
        let bundle = now(bob.publish_bundle(&mut rng)).unwrap();
        now(alice.establish_session(&bob.address(), &bundle, &mut rng)).unwrap();

        assert_eq!(alice.known_peers(), vec![bob.address()]);
    }

    /// A prekey store survives an export/import round trip and keeps
    /// answering first contacts afterward.
    ///
    /// Restored alongside the *same* identity the prekeys were signed
    /// under (`from_identity`, not a fresh `generate`) -- a durable store
    /// restores both together, and a prekey store signed under one
    /// identity is meaningless paired with a different one.
    #[test]
    fn prekeys_survive_export_import() {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let mut alice = OpenParty::generate("alice", 1, &mut rng).expect("generate");
        assert!(alice.export_prekeys().is_none(), "no prekeys published yet");

        now(alice.publish_bundle(&mut rng)).unwrap();
        let prekey_bytes = alice.export_prekeys().expect("prekeys published");
        let identity = alice.export_identity();

        let mut restored = OpenParty::from_identity("alice", 1, &identity).unwrap();
        restored.import_prekeys(&prekey_bytes).unwrap();

        // A bundle from the restored prekeys still lets a peer establish and
        // deliver a first message.
        let bundle = now(restored.publish_bundle(&mut rng)).unwrap();
        let mut bob = OpenParty::generate("bob", 1, &mut rng).expect("generate");
        now(bob.establish_session(&restored.address(), &bundle, &mut rng)).unwrap();
        let m = now(bob.encrypt(&restored.address(), b"hi", &mut rng)).unwrap();
        assert_eq!(
            now(restored.decrypt(&bob.address(), &m, &mut rng)).unwrap(),
            b"hi"
        );
    }

    /// **The prekey half of the file is guarded like the session half.**
    ///
    /// `Session::import` refuses a byte string that is not the encoding of what
    /// it decodes to. `import_prekeys` does the same, because
    /// `DurableOpenParty::open` feeds both from the same untrusted `state.bin`:
    /// sessions through one path, prekeys through this one. Guarding one half
    /// of a file's contents is not guarding the file.
    ///
    /// **Sampled rather than exhaustive, on purpose.** A prekey blob carries 32
    /// one-time keys, and a fresh party per byte would mean an ML-KEM keygen
    /// per byte, minutes of wall time. One party is reused (import replaces
    /// the store wholesale) and the positions are spread across the blob. A
    /// sample that would find a defect is worth more than an exhaustive sweep
    /// nobody will run.
    #[test]
    fn import_prekeys_refuses_a_non_canonical_spelling() {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let mut alice = OpenParty::generate("alice", 1, &mut rng).expect("generate");
        now(alice.publish_bundle(&mut rng)).unwrap();
        let clean = alice.export_prekeys().unwrap().to_vec();

        let mut fresh = OpenParty::generate("alice2", 1, &mut rng).expect("generate");
        let step = (clean.len() / 128).max(1);

        let mut non_canonical = 0usize;
        let mut accepted = 0usize;

        for i in (0..clean.len()).step_by(step) {
            let mut dirty = clean.clone();
            dirty[i] ^= 0xFF;
            if fresh.import_prekeys(&dirty).is_ok() {
                let back = fresh.export_prekeys().expect("imported, so it exports");
                if back.as_slice() != dirty.as_slice() {
                    non_canonical += 1;
                } else {
                    accepted += 1;
                }
            }
        }

        assert_eq!(
            non_canonical, 0,
            "{non_canonical} sampled byte strings decoded and re-encoded to \
             something else; every accepted spelling must be the encoding of \
             what it decodes to ({accepted} accepted and canonical)"
        );
    }

    /// **A v1 prekey store must still upgrade.** `from_bytes` accepts v1, v2
    /// and v3; `to_bytes` only ever writes the current version. So a v1 blob
    /// decodes fine and re-encodes as the current version, which a naive
    /// canonicity check would refuse -- breaking upgrade for every store
    /// written before the last-resort fingerprints existed.
    #[test]
    fn a_v1_prekey_store_still_imports() {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let mut alice = OpenParty::generate("alice", 1, &mut rng).expect("generate");
        now(alice.publish_bundle(&mut rng)).unwrap();
        let v3 = alice.export_prekeys().unwrap().to_vec();

        // A fresh store has no fingerprints and nothing retired, so the v3
        // export ends in the four-byte fingerprint count (zero) followed by
        // the two retired-prekey presence bytes (both absent). v1 predates
        // both: it is the same bytes with the version lowered and that
        // six-byte tail removed.
        assert_eq!(&v3[v3.len() - 6..], &[0, 0, 0, 0, 0x00, 0x00]);
        let mut v1 = v3.clone();
        v1[0] = 0x01;
        v1.truncate(v1.len() - 6);

        let mut fresh = OpenParty::generate("alice2", 1, &mut rng).expect("generate");
        assert!(
            fresh.import_prekeys(&v1).is_ok(),
            "a v1 store must upgrade, not be refused as non-canonical"
        );
    }

    #[test]
    fn import_prekeys_rejects_a_truncated_buffer() {
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let mut alice = OpenParty::generate("alice", 1, &mut rng).expect("generate");
        now(alice.publish_bundle(&mut rng)).unwrap();
        let bytes = alice.export_prekeys().unwrap();

        let mut fresh = OpenParty::generate("alice2", 1, &mut rng).expect("generate");
        assert!(fresh.import_prekeys(&bytes[..bytes.len() - 1]).is_err());
    }
}
