//! The seam, as a trait.
//!
//! `tacenta-core::crypto` is the single place this product names its
//! cryptographic provider. This is the surface the product needs from that
//! provider, written as a trait, so the client above the seam is written
//! against the contract rather than against `open-tacenta`'s types.
//!
//! Two properties fall out of writing it as a trait:
//!
//! - **Substitutability.** The client is written against the trait, so it
//!   never names a provider's concrete types.
//! - **A provider tag on persisted state.** A session is bound to the
//!   provider that established it, because keys are derived under
//!   provider-specific labels; the state envelope records which provider a
//!   session belongs to (see `SessionProvider`).
//!
//! ## Why every boundary is bytes
//!
//! Ciphertext goes in and out as framed bytes, bundles are serialized,
//! identities are exported. The few provider-specific types that remain are
//! turned into bytes here.
//!
//! So the trait deals in bytes and primitives at every boundary, and the
//! contract is stated as behaviour, not bytes: behaviour is what crosses this
//! boundary.

use rand::{CryptoRng, Rng};

/// Where a party is: who, and which of their devices.
///
/// A pair rather than a provider's own address type, because the client
/// above the seam has no business naming one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
    pub user: String,
    pub device: u8,
}

impl Address {
    pub fn new(user: impl Into<String>, device: u8) -> Address {
        Address {
            user: user.into(),
            device,
        }
    }
}

/// One participant's cryptography: an identity, its prekeys, and its sessions.
///
/// What an implementation is required to do is stated as behaviour: a
/// sequence of calls produces the expected plaintexts at the far end, and
/// fails in the expected cases. The `conformance` suite is that statement as
/// code.
pub trait CryptoProvider: Sized {
    /// Whatever this provider fails with. Deliberately opaque: the oracle
    /// compares *whether* an operation failed and against a shared
    /// classification, not the provider's own error text.
    type Error: core::fmt::Debug;

    /// A name for this provider, for test output and for recording which one a
    /// session was established under.
    const NAME: &'static str;

    /// Classify a failure into terms the provider can be held to.
    ///
    /// On the trait rather than on the error type, because that is what lets a
    /// caller written against the seam check a provider without naming its
    /// errors.
    fn classify(err: &Self::Error) -> Failure;

    /// Generate a fresh identity and an empty store.
    fn generate<R: Rng + CryptoRng>(
        user: &str,
        device: u8,
        csprng: &mut R,
    ) -> Result<Self, Self::Error>;

    /// Serialize the identity secret, so a client can reconnect as the same
    /// party rather than a new one. **Carries a private key.**
    fn export_identity(&self) -> Vec<u8>;

    /// Restore from [`export_identity`]: the same identity, an empty store.
    fn from_identity(user: &str, device: u8, bytes: &[u8]) -> Result<Self, Self::Error>;

    /// This party's address.
    fn address(&self) -> Address;

    /// This party's public identity key, serialized. A server registers it; a
    /// peer trusts it through the session rather than through the server.
    fn identity_key(&self) -> Vec<u8>;

    /// Sign a transport challenge with the identity private key.
    fn sign_challenge<R: Rng + CryptoRng>(&self, challenge: &[u8], csprng: &mut R) -> Vec<u8>;

    /// Verify a challenge signature against a serialized identity key.
    ///
    /// **The server side of the seam.** The rest of the trait is what a party
    /// does, and the server does not hold a party: it holds identity bytes
    /// from the directory and asks whether they signed a challenge. That is
    /// this function, and it is why the trait has an associated function
    /// rather than only methods.
    ///
    /// It is the one place the two sides of a deployment must agree with each
    /// other rather than merely behave alike: a client signing under one
    /// provider and a server verifying under another would reject every
    /// connection, so both sides name `DefaultProvider`.
    fn verify_challenge(identity: &[u8], challenge: &[u8], signature: &[u8]) -> bool;

    /// Publish a prekey bundle, serialized. The private halves stay here.
    fn publish_bundle<R: Rng + CryptoRng>(
        &mut self,
        csprng: &mut R,
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>>;

    /// One published bundle per one-time prekey this party can offer, for a
    /// directory that dispenses them (decision 0074).
    ///
    /// **Defaults to empty, and that is the honest answer for a provider
    /// without one-time prekeys.** Decision 0050 keeps one-time keys out of
    /// the multi-use bundle, because a directory serves that bundle to
    /// everybody; a provider with no batch to offer leaves the directory to
    /// fall back to the multi-use bundle. A provider that has one-time
    /// prekeys overrides this, and the shipped provider does.
    ///
    /// Separate from `publish_bundle` rather than replacing it: the multi-use
    /// bundle is still needed as the exhausted-pool fallback, so a caller
    /// wants both.
    fn publish_one_time_batch<R: Rng + CryptoRng>(
        &mut self,
        _csprng: &mut R,
    ) -> impl Future<Output = Result<Vec<Vec<u8>>, Self::Error>> {
        core::future::ready(Ok(Vec::new()))
    }

    /// Open a session toward `peer` from its published bundle.
    fn establish_session<R: Rng + CryptoRng>(
        &mut self,
        peer: &Address,
        bundle: &[u8],
        csprng: &mut R,
    ) -> impl Future<Output = Result<(), Self::Error>>;

    /// Encrypt for `peer`, returning framed ciphertext ready to be an envelope
    /// payload.
    fn encrypt<R: Rng + CryptoRng>(
        &mut self,
        peer: &Address,
        plaintext: &[u8],
        csprng: &mut R,
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>>;

    /// Decrypt framed ciphertext from `peer`.
    fn decrypt<R: Rng + CryptoRng>(
        &mut self,
        peer: &Address,
        framed: &[u8],
        csprng: &mut R,
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>>;

    /// Serialize the live sessions with `peers`, so a client can resume a
    /// conversation mid-ratchet across a restart rather than re-establishing.
    ///
    /// **Carries session secrets**, and a peer with no stored session is
    /// skipped rather than being an error.
    ///
    /// On the trait because the client needs it and could not be written
    /// against the seam without it: persistence is a thing a client does, so
    /// the seam has to carry it even though the conformance suite is about
    /// the messaging behaviour.
    fn export_sessions(
        &self,
        peers: &[Address],
    ) -> impl Future<Output = Result<Vec<u8>, Self::Error>>;

    /// Restore sessions from [`export_sessions`], returning the peers restored
    /// so a caller can rebuild its own record of who it is talking to.
    ///
    /// Trust in the restored identities is inherited from when they were first
    /// established; importing does not re-verify them.
    ///
    /// [`export_sessions`]: CryptoProvider::export_sessions
    fn import_sessions(
        &mut self,
        bytes: &[u8],
    ) -> impl Future<Output = Result<Vec<Address>, Self::Error>>;

    /// This party's published prekey store, encoded for persistence, or `None`
    /// if there is nothing to export — `publish_bundle` was never called, or
    /// the provider does not model a prekey store.
    ///
    /// **This is the half of exported state that makes first contact
    /// survivable.** A message a *new* peer sends to a published one-time
    /// prekey while this device is offline is encrypted to that prekey; without
    /// its private half in the exported state, a restored device cannot decrypt
    /// it. [`export_sessions`] covers conversations already live and, by
    /// construction, cannot cover one that has not yet begun.
    ///
    /// Carries private key material, so the returned bytes are as sensitive as
    /// the session export. Synchronous because a prekey store is in memory; no
    /// store I/O is involved.
    ///
    /// [`export_sessions`]: CryptoProvider::export_sessions
    fn export_prekeys(&self) -> Option<Vec<u8>>;

    /// Restore a prekey store from [`export_prekeys`], replacing whatever this
    /// party currently holds.
    ///
    /// Reached only when a blob carries a prekeys section, which only a provider
    /// whose `export_prekeys` returned `Some` writes — so a provider that does
    /// not model prekeys is never asked to import them from its own output. The
    /// implementation is expected to reject bytes it would not itself produce,
    /// on the same reasoning as `import_sessions`: one untrusted blob feeds
    /// both halves, and guarding one is not guarding the file.
    ///
    /// [`export_prekeys`]: CryptoProvider::export_prekeys
    fn import_prekeys(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;

    /// Discard every live session, keeping the identity and prekeys.
    ///
    /// Decision 0078's rollback response (decision 3): when the directory
    /// reports that a restored state is older than one already witnessed, its
    /// ratchets must not be resumed. The sessions are dropped and
    /// re-established fresh on the next message, so an attacker who rolled the
    /// state back gets a client that has forgotten the chain keys they wanted
    /// replayed — the identity survives, the sessions do not.
    fn clear_sessions(&mut self);
}

/// How an operation failed, in terms any provider can be held to.
///
/// Providers' own error types say different things in different words, and
/// neither is wrong. What the conformance suite can require is that they fail in
/// the same *cases*, so failures are classified into this before comparison.
///
/// Kept deliberately coarse. A finer classification would be asserting agreement
/// implementations were never built to have, and a suite that fails
/// for that reason teaches nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The ciphertext was not well-formed, or not for this session.
    Undecryptable,
    /// The bundle was rejected: a bad signature, or a field that will not parse.
    BadBundle,
    /// No session with that peer, where one was required.
    NoSession,
    /// Anything else. Two providers landing here have not been shown to agree.
    Other,
}
