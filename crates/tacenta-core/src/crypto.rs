//! The cryptographic provider seam.
//!
//! This module is the seam itself: the `CryptoProvider` trait, the provider
//! the product ships, and the one function a server needs that is not a
//! method on a party.
//!
//! The cryptography is tacenta-core's, consumed as the pinned `open-tacenta`
//! dependency. What this repository claims about it is in `docs/claims.md`,
//! and what it does not claim is in tacenta-core's
//! `tacenta-proofs/LIMITATIONS.md`.

/// The provider the product ships with.
///
/// **The single place the provider is named.** Every consumer writes
/// `DefaultProvider` (or is generic over `CryptoProvider`) rather than a
/// concrete type, so the name lives here and nowhere else.
///
/// The provider ratchets post-quantum: `Session` drives the Triple Ratchet
/// and the braid through a candidate/commit path. The suite in `conformance`
/// is what makes "the provider meets the seam's contract" a checked statement
/// rather than a hope.
pub type DefaultProvider = open::OpenParty;

/// Verify a challenge signature against a published identity key.
///
/// The one operation a server needs from the provider without holding a
/// party: it holds identity bytes from the directory and asks whether a
/// signature over its challenge verifies under them. Routed through
/// `DefaultProvider`, so it follows the provider rather than pinning one, and
/// so no server crate has to name a key type of its own.
pub fn verify_challenge(identity: &[u8], challenge: &[u8], signature: &[u8]) -> bool {
    <DefaultProvider as CryptoProvider>::verify_challenge(identity, challenge, signature)
}

/// A durable, crash-atomic wrapper around `OpenParty`. See its own module
/// docs for why this is a concrete type rather than another
/// `CryptoProvider` implementation.
pub mod durable_open;
/// The tacenta-core provider.
pub mod open;
pub mod provider;
pub use provider::{Address, CryptoProvider, Failure};

/// The behavioural bar a provider must clear, generic over the provider.
///
/// Available outside this crate behind the `conformance` feature, off by
/// default, for test tooling that drives a provider through the suite.
#[cfg(any(test, feature = "conformance"))]
pub mod conformance;
