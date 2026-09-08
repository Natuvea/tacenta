//! The wrapping-key seam for authenticated persisted state — decision 0078's
//! anchor B.
//!
//! **Why a seam and not a concrete store.** Anchor B authenticates the
//! persisted-state generation so that a file-rewriter cannot forge it. The
//! authenticator needs a key, and the whole construction rests
//! on that key living somewhere the file-rewriter *cannot reach*: an attacker
//! who can rewrite the state file and the key has defeated it. That "somewhere"
//! is platform-specific — iOS/macOS Keychain, Android Keystore, an OS keyring on
//! desktop — and none of those exists in this crate. So the key source is a
//! trait the platform binding implements, not a thing tacenta-client ships.
//!
//! **What the implementation must guarantee**, and what B is worth is exactly
//! these:
//!
//! - *Unreachable to a file-rewriter.* If the key can be read or rewritten by an
//!   attacker who can rewrite `state.bin`, B authenticates nothing. A key kept
//!   in an ordinary file beside the blob is the canonical wrong answer.
//! - *Stable across restarts.* The same install must recover the same key, or
//!   every restart reads as tampering and discards every session.
//! - *Per-install.* Two installs need not share a key; the key identifies the
//!   local store, not the user.
//!
//! The seam is deliberately small — a 32-byte wrapping key plus a monotonic
//! rollback counter (three methods: [`SecureStore::wrap_key`],
//! [`SecureStore::rollback_counter`], [`SecureStore::bump_rollback_counter`]) —
//! because the sealing, the generation binding and the freshness policy already
//! live in `tacenta_core::persist` (`seal`/`unseal`/`freshness`). All this owes
//! them is a key they can trust and a counter that only moves forward.

/// Platform secure storage backing rollback-resistant persisted state
/// ([`export_state_sealed`](crate::Client::export_state_sealed) and its restore
/// siblings): a wrapping **key** and a monotonic **counter**, both held where an
/// attacker who can rewrite the state file cannot reach them.
///
/// See the module documentation in `secure_store.rs` for the guarantees an
/// implementation must meet (the module is private, so rustdoc does not show it);
/// they are the entirety of what anchor B is worth.
pub trait SecureStore {
    /// Return the wrapping key, creating and persisting it on first use.
    ///
    /// Called once per export and once per restore. Implementations may cache,
    /// but the returned key must be identical across process restarts for the
    /// same install — a key that changed between runs would make every restore
    /// look like tampering.
    fn wrap_key(&self) -> Result<[u8; 32], SecureStoreError>;

    /// Read the highest rollback counter this store has committed, or `0` if it
    /// never has. **Read-only**; used on restore to tell whether the state being
    /// restored is older than the newest this device produced.
    ///
    /// The counter must be **rollback-resistant to a file-rewriter** — kept in
    /// secure storage, never beside the state blob — and it must survive
    /// restarts. This is the freshness anchor that catches a same-generation
    /// rollback: an attacker who keeps an old sealed file and restores it later
    /// presents a counter below this high-water mark.
    fn rollback_counter(&self) -> Result<u64, SecureStoreError>;

    /// Atomically increment the rollback counter, persist it, and return the new
    /// value. **Never decreases.** Called on **every send and every
    /// ratchet-advancing receive** (the client commits one advance each), *not*
    /// on export — [`export_state_sealed`](crate::Client::export_state_sealed)
    /// binds the *current* value read via [`rollback_counter`](Self::rollback_counter).
    /// Because the counter tracks ratchet advances rather than export cadence, a
    /// later restore of any state older than the latest send presents a lower
    /// counter than this store now holds and is caught as a rollback.
    fn bump_rollback_counter(&self) -> Result<u64, SecureStoreError>;
}

/// Why a [`SecureStore`] could not produce a key.
#[derive(Debug)]
pub enum SecureStoreError {
    /// This platform or build has no secure storage to hold the key. **A caller
    /// that meets this must not silently fall back to an unprotected key** —
    /// that would look like anchor B while being none. It should use the
    /// unsealed path (which makes no rollback claim) and say so. A store
    /// that exists but cannot be reached right now (a Keychain before first
    /// unlock, a Keystore that needs the user) is this too, with the reason:
    /// the client reports it as its own kind, so the app can retry after
    /// the unlock rather than treat it as tampering.
    Unavailable(String),
    /// The secure-storage backend was present but failed. The string is for a
    /// log line, not for matching on.
    Backend(String),
}

impl std::fmt::Display for SecureStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecureStoreError::Unavailable(reason) => {
                write!(f, "secure storage is not available: {reason}")
            }
            SecureStoreError::Backend(e) => write!(f, "secure storage failed: {e}"),
        }
    }
}

impl std::error::Error for SecureStoreError {}
