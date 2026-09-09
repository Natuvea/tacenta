//! A durable, crash-atomic wrapper around [`OpenParty`].
//!
//! Nothing in `open-tacenta` or `OpenParty` writes to disk: `Session::export`,
//! `PrekeyStore::to_bytes`, and `export_sessions`/`export_prekeys` all produce
//! bytes and stop there. This module is what a real caller persists those
//! bytes with, with the crash-safety the protocol asks for:
//! "authenticate, save session, mark the KEM prekey used, delete the
//! one-time prekey" lands as one atomic unit, or none of it does.
//!
//! **This module has no production caller, and the reason is structural:**
//! `DurableOpenParty` is not a `CryptoProvider`, so `Client<P>` cannot take it
//! at all. It is unusable from `Client` rather than merely unused. Decision
//! 0077 makes the exported blob the persistence contract and puts the write
//! sequence in [`crate::persist`], where every caller reaches it.
//!
//! What stays here is the fault-injection harness: a full two-party
//! conversation across a real restart of both sides, and a simulated crash
//! mid-establishment. Those tests are the evidence that the write sequence is
//! correct, which is what lets it be trusted where it is used.
//!
//! ## Why one combined file, not three
//!
//! Identity never changes after creation, so it gets its own file, written
//! once. Prekeys and sessions change *together* at session establishment
//! (an incoming initial message both consumes a one-time prekey and creates
//! a session) and *separately* at every ordinary `encrypt`/`decrypt` (which
//! only advances a session's ratchet). Choreographing that across two files
//! would need its own recovery protocol for "file A renamed, file B did
//! not." Serializing the prekey store and every session into one buffer and
//! atomically rewriting *that* file after every mutating call sidesteps the
//! question: there is only ever one file to be out of sync with itself.
//!
//! ## At-rest scope
//!
//! Nothing here encrypts the files it writes. tacenta-core's
//! `tacenta-spec/protocol/key-deletion.md` already states that erasure
//! guarantees are in-memory-only and that
//! `Session::export`/`import` is a deliberate exception to that boundary, not
//! a quiet expansion of it; this wrapper inherits that same boundary rather
//! than resolving it. At-rest protection (disk encryption, or an
//! encryption layer above this one) is the caller's job.

use super::open::{OpenError, OpenParty};
use super::provider::{Address, CryptoProvider};
use crate::persist::write_atomically;
use rand::{CryptoRng, Rng};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const IDENTITY_FILE: &str = "identity.bin";
const STATE_FILE: &str = "state.bin";

/// This module's own persistence-format version for the combined
/// prekeys+sessions state file, separate from any format version inside the
/// bytes it wraps.
const STATE_VERSION: u8 = 0x01;

fn invalid_data(msg: &'static str) -> DurableError {
    DurableError::Io(io::Error::new(io::ErrorKind::InvalidData, msg))
}

/// What this wrapper fails with: the inner provider's own error, or an I/O
/// failure reading or persisting state.
#[derive(Debug)]
pub enum DurableError {
    Provider(OpenError),
    Io(io::Error),
}

/// [`OpenParty`], plus a directory it durably persists identity, prekeys,
/// and sessions to after every call that changes them.
///
/// # This type is not on a shipping path
///
/// **Nothing a customer runs constructs it, and that is deliberate.** It is
/// the reference integration and the fault-injection harness: its tests are
/// the evidence that the write sequence in [`crate::persist`] is correct, and
/// they are why that sequence can be trusted where it *is* used.
///
/// It is not a `CryptoProvider`, so `Client<P>` cannot take it. The trait's
/// `generate`/`from_identity` have no room for a directory argument, and a
/// durable store is a deployment choice layered on the provider rather than
/// a provider of its own. Using this type directly means abandoning `Client`,
/// which no shipping path does and no SDK user would.
///
/// **Decision 0077 makes the exported blob the persistence contract and puts
/// the valuable part -- the write sequence -- in [`crate::persist`], where
/// every caller reaches it.** Crash-atomic storage that only a type the SDK's
/// own client cannot construct could reach would leave shipping callers to
/// write bytes however they liked.
///
/// If this type ever goes a release without being exercised, it should be
/// deleted rather than left to imply an integration that does not exist.
pub struct DurableOpenParty {
    inner: OpenParty,
    dir: PathBuf,
}

impl DurableOpenParty {
    /// Generate a fresh party and persist it: an identity file, written
    /// once, and an empty combined prekeys+sessions state file.
    pub fn create<R: Rng + CryptoRng>(
        dir: &Path,
        user: &str,
        device: u8,
        csprng: &mut R,
    ) -> Result<DurableOpenParty, DurableError> {
        fs::create_dir_all(dir).map_err(DurableError::Io)?;
        let inner = OpenParty::generate(user, device, csprng).map_err(DurableError::Provider)?;
        write_atomically(&dir.join(IDENTITY_FILE), &inner.export_identity())
            .map_err(DurableError::Io)?;
        let party = DurableOpenParty {
            inner,
            dir: dir.to_path_buf(),
        };
        party.write_state(&Vec::new(), &empty_sessions_blob())?;
        Ok(party)
    }

    /// Restore a party from what `create` (or a prior mutating call) wrote.
    pub async fn open(
        dir: &Path,
        user: &str,
        device: u8,
    ) -> Result<DurableOpenParty, DurableError> {
        let identity_bytes = fs::read(dir.join(IDENTITY_FILE)).map_err(DurableError::Io)?;
        let mut inner = OpenParty::from_identity(user, device, &identity_bytes)
            .map_err(DurableError::Provider)?;

        let state_bytes = fs::read(dir.join(STATE_FILE)).map_err(DurableError::Io)?;
        let (prekeys, sessions) = decode_state(&state_bytes)?;
        if let Some(prekeys) = prekeys {
            inner
                .import_prekeys(prekeys)
                .map_err(DurableError::Provider)?;
        }
        inner
            .import_sessions(sessions)
            .await
            .map_err(DurableError::Provider)?;

        Ok(DurableOpenParty {
            inner,
            dir: dir.to_path_buf(),
        })
    }

    /// This party's address.
    pub fn address(&self) -> Address {
        self.inner.address()
    }

    /// This party's public identity key, serialized.
    pub fn identity_key(&self) -> Vec<u8> {
        self.inner.identity_key()
    }

    /// Publish a prekey bundle, persisting the (possibly newly created)
    /// prekey store before returning.
    pub async fn publish_bundle<R: Rng + CryptoRng>(
        &mut self,
        csprng: &mut R,
    ) -> Result<Vec<u8>, DurableError> {
        let bundle = self
            .inner
            .publish_bundle(csprng)
            .await
            .map_err(DurableError::Provider)?;
        self.persist().await?;
        Ok(bundle)
    }

    /// Open a session toward `peer`, persisting it before returning.
    pub async fn establish_session<R: Rng + CryptoRng>(
        &mut self,
        peer: &Address,
        bundle: &[u8],
        csprng: &mut R,
    ) -> Result<(), DurableError> {
        self.inner
            .establish_session(peer, bundle, csprng)
            .await
            .map_err(DurableError::Provider)?;
        self.persist().await?;
        Ok(())
    }

    /// Encrypt for `peer`, persisting the advanced ratchet before returning.
    /// Skipping this would let a restart resume from stale state and
    /// re-derive a message key already used on the wire -- key reuse, not
    /// just data loss -- so this persists on every call, not only at
    /// establishment.
    pub async fn encrypt<R: Rng + CryptoRng>(
        &mut self,
        peer: &Address,
        plaintext: &[u8],
        csprng: &mut R,
    ) -> Result<Vec<u8>, DurableError> {
        let ciphertext = self
            .inner
            .encrypt(peer, plaintext, csprng)
            .await
            .map_err(DurableError::Provider)?;
        self.persist().await?;
        Ok(ciphertext)
    }

    /// Decrypt from `peer`. If `framed` is an initial message, this is
    /// exactly the protocol's named transaction: authenticate, save the new
    /// session, and consume the one-time prekeys it named, all reflected in
    /// the one atomic write `persist` performs -- so a crash before it
    /// completes leaves the prekeys and the session both as they were
    /// before this call, and a crash after leaves both fully updated. There
    /// is no state in between.
    pub async fn decrypt<R: Rng + CryptoRng>(
        &mut self,
        peer: &Address,
        framed: &[u8],
        csprng: &mut R,
    ) -> Result<Vec<u8>, DurableError> {
        let plaintext = self
            .inner
            .decrypt(peer, framed, csprng)
            .await
            .map_err(DurableError::Provider)?;
        self.persist().await?;
        Ok(plaintext)
    }

    /// Encode this party's current prekeys and every known session, and
    /// atomically rewrite the combined state file.
    async fn persist(&self) -> Result<(), DurableError> {
        let prekeys = self.inner.export_prekeys();
        let peers = self.inner.known_peers();
        let sessions = self
            .inner
            .export_sessions(&peers)
            .await
            .map_err(DurableError::Provider)?;
        self.write_state(prekeys.as_deref().map_or(&[], |b| b.as_slice()), &sessions)?;
        Ok(())
    }

    fn write_state(&self, prekeys: &[u8], sessions: &[u8]) -> Result<(), DurableError> {
        let mut out = Vec::new();
        out.push(STATE_VERSION);
        if prekeys.is_empty() {
            out.push(0x00);
        } else {
            out.push(0x01);
            out.extend_from_slice(&(prekeys.len() as u32).to_be_bytes());
            out.extend_from_slice(prekeys);
        }
        out.extend_from_slice(&(sessions.len() as u32).to_be_bytes());
        out.extend_from_slice(sessions);
        write_atomically(&self.dir.join(STATE_FILE), &out).map_err(DurableError::Io)
    }
}

/// An `export_sessions` blob for zero peers: just its own "0 sessions"
/// framing, valid input to `import_sessions` on a fresh party.
fn empty_sessions_blob() -> Vec<u8> {
    0u32.to_be_bytes().to_vec()
}

/// Decode the combined state file, returning the prekey bytes (if present)
/// and the sessions blob.
fn decode_state(bytes: &[u8]) -> Result<(Option<&[u8]>, &[u8]), DurableError> {
    if bytes.is_empty() {
        return Err(invalid_data("state file is empty"));
    }
    if bytes[0] != STATE_VERSION {
        return Err(invalid_data("state file has an unrecognised version"));
    }
    if bytes.len() < 2 {
        return Err(invalid_data("state file is too short"));
    }
    let prekeys_present = bytes[1];
    let mut pos = 2;

    let prekeys = match prekeys_present {
        0x00 => None,
        0x01 => {
            if bytes.len() < pos + 4 {
                return Err(invalid_data("state file is too short"));
            }
            let len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if bytes.len() < pos + len {
                return Err(invalid_data("state file is too short"));
            }
            let field = &bytes[pos..pos + len];
            pos += len;
            Some(field)
        }
        _ => return Err(invalid_data("state file has a malformed presence byte")),
    };

    if bytes.len() < pos + 4 {
        return Err(invalid_data("state file is too short"));
    }
    let sessions_len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap()) as usize;
    pos += 4;
    if bytes.len() < pos + sessions_len {
        return Err(invalid_data("state file is too short"));
    }
    let sessions = &bytes[pos..pos + sessions_len];
    pos += sessions_len;

    if pos != bytes.len() {
        return Err(invalid_data("state file has trailing bytes"));
    }

    Ok((prekeys, sessions))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now<T>(fut: impl std::future::Future<Output = T>) -> T {
        use futures_util::FutureExt;
        fut.now_or_never()
            .expect("in-memory session future did not complete synchronously")
    }

    fn rng() -> impl Rng + CryptoRng {
        use rand::TryRngCore;
        rand::rngs::OsRng.unwrap_err()
    }

    #[test]
    fn atomic_write_creates_and_then_fully_replaces() {
        let dir = tempdir();
        let path = dir.join("f.bin");

        write_atomically(&path, b"first").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"first");

        write_atomically(&path, b"a much longer second write").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"a much longer second write");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The crash this whole module exists to defend against: a temp file
    /// left behind (the process died after the write but before the
    /// rename) must not disturb the target. The next `atomic_write` cleans
    /// up by overwriting its own temp file and completing the rename
    /// normally.
    #[test]
    fn a_stray_temp_file_does_not_disturb_the_target() {
        let dir = tempdir();
        let path = dir.join("f.bin");
        write_atomically(&path, b"original").unwrap();

        // Simulate a crash between the temp write and the rename: write the
        // temp file by hand and stop, exactly what a killed process would
        // leave behind.
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        fs::write(&tmp, b"never renamed").unwrap();

        assert_eq!(
            fs::read(&path).unwrap(),
            b"original",
            "the target must be untouched while the temp file sits unrenamed"
        );

        write_atomically(&path, b"second").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"second");

        std::fs::remove_dir_all(&dir).ok();
    }

    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);

        let mut p = std::env::temp_dir();
        p.push(format!(
            "tacenta-durable-open-test-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// A party created, then reopened with nothing else having happened,
    /// has the same address and identity key -- the simplest round trip.
    #[test]
    fn a_fresh_party_survives_create_and_open() {
        let dir = tempdir();
        let mut r = rng();
        let created = DurableOpenParty::create(&dir, "alice", 1, &mut r).unwrap();
        let identity_key = created.identity_key();

        let reopened = now(DurableOpenParty::open(&dir, "alice", 1)).unwrap();
        assert_eq!(reopened.identity_key(), identity_key);
        assert_eq!(reopened.address(), created.address());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The named write sequence, run for real rather than
    /// assumed from the atomic-write primitive being sound in isolation:
    /// establishing a session as a responder both consumes a one-time
    /// prekey and creates a session, in one call. If the process dies after
    /// that in-memory mutation but before `persist` writes it, reopening
    /// from disk must show *neither* change -- the prekey still
    /// unconsumed, no session recorded -- never a partial state where one
    /// lands and the other does not. Only once `persist` actually completes
    /// does reopening show both.
    #[test]
    fn establishment_is_atomic_across_a_simulated_crash() {
        let mut r = rng();
        let bob_dir = tempdir();
        let alice_dir = tempdir();

        let mut bob = DurableOpenParty::create(&bob_dir, "bob", 1, &mut r).unwrap();
        let bundle_before = now(bob.publish_bundle(&mut r)).unwrap();

        let mut alice = DurableOpenParty::create(&alice_dir, "alice", 1, &mut r).unwrap();
        now(alice.establish_session(&bob.address(), &bundle_before, &mut r)).unwrap();
        let initial = now(alice.encrypt(&bob.address(), b"hello bob", &mut r)).unwrap();

        // Simulate a crash: drive bob's inner `OpenParty` directly, which
        // authenticates the message, consumes the one-time prekey, and
        // records the session -- entirely in memory -- but bypasses the
        // wrapper that would call `persist` afterward. `bob` is then
        // dropped without that mutation ever reaching disk.
        now(bob.inner.decrypt(&alice.address(), &initial, &mut r)).unwrap();
        assert!(
            bob.inner.known_peers().contains(&alice.address()),
            "the in-memory mutation should have happened"
        );
        drop(bob);

        // Reopened from disk, bob shows neither change: no session with
        // Alice, and the same bundle it would have published before the
        // crash (the one-time prekey never left the store).
        let mut bob_after_crash = now(DurableOpenParty::open(&bob_dir, "bob", 1)).unwrap();
        assert!(
            !bob_after_crash
                .inner
                .known_peers()
                .contains(&alice.address()),
            "an unpersisted session must not survive a simulated crash"
        );
        let bundle_after_crash = now(bob_after_crash.publish_bundle(&mut r)).unwrap();
        assert_eq!(
            bundle_after_crash, bundle_before,
            "an unpersisted prekey consumption must not survive a simulated crash"
        );

        // Alice repeats her initial message until she hears back, so the
        // same bytes drive the establishment again -- this time through the
        // wrapper properly, so `persist` actually runs.
        now(bob_after_crash.decrypt(&alice.address(), &initial, &mut r)).unwrap();
        drop(bob_after_crash);

        let bob_after_real_commit = now(DurableOpenParty::open(&bob_dir, "bob", 1)).unwrap();
        assert!(
            bob_after_real_commit
                .inner
                .known_peers()
                .contains(&alice.address()),
            "a session persisted for real must survive reopening"
        );

        std::fs::remove_dir_all(&bob_dir).ok();
        std::fs::remove_dir_all(&alice_dir).ok();
    }

    /// The full shape: publish, establish, exchange messages, restart both
    /// sides, and keep going. If prekeys or sessions did not truly persist,
    /// either the restarted responder could not decrypt Alice's next
    /// message, or the restarted initiator would restart the ratchet from
    /// scratch and produce a message the still-live peer could not decrypt.
    #[test]
    fn a_conversation_survives_both_parties_restarting() {
        let mut r = rng();
        let alice_dir = tempdir();
        let bob_dir = tempdir();

        let mut alice = DurableOpenParty::create(&alice_dir, "alice", 1, &mut r).unwrap();
        let mut bob = DurableOpenParty::create(&bob_dir, "bob", 1, &mut r).unwrap();

        let bundle = now(bob.publish_bundle(&mut r)).unwrap();
        now(alice.establish_session(&bob.address(), &bundle, &mut r)).unwrap();

        let m1 = now(alice.encrypt(&bob.address(), b"hello bob", &mut r)).unwrap();
        assert_eq!(
            now(bob.decrypt(&alice.address(), &m1, &mut r)).unwrap(),
            b"hello bob"
        );

        // Both restart: dropped, and rebuilt from what was on disk.
        drop(alice);
        drop(bob);
        let mut alice = now(DurableOpenParty::open(&alice_dir, "alice", 1)).unwrap();
        let mut bob = now(DurableOpenParty::open(&bob_dir, "bob", 1)).unwrap();

        let m2 = now(bob.encrypt(&alice.address(), b"hi alice", &mut r)).unwrap();
        assert_eq!(
            now(alice.decrypt(&bob.address(), &m2, &mut r)).unwrap(),
            b"hi alice"
        );
        let m3 = now(alice.encrypt(&bob.address(), b"still here", &mut r)).unwrap();
        assert_eq!(
            now(bob.decrypt(&alice.address(), &m3, &mut r)).unwrap(),
            b"still here"
        );

        std::fs::remove_dir_all(&alice_dir).ok();
        std::fs::remove_dir_all(&bob_dir).ok();
    }

    /// `open` on a directory whose state file was truncated mid-write (the
    /// crash `atomic_write` is built to prevent, forced here to prove the
    /// decoder itself also refuses rather than silently misreading) is
    /// rejected rather than partially applied.
    #[test]
    fn open_rejects_a_truncated_state_file() {
        let dir = tempdir();
        let mut r = rng();
        let alice = DurableOpenParty::create(&dir, "alice", 1, &mut r).unwrap();
        drop(alice);

        let state_path = dir.join(STATE_FILE);
        let bytes = fs::read(&state_path).unwrap();
        fs::write(&state_path, &bytes[..bytes.len() - 1]).unwrap();

        assert!(now(DurableOpenParty::open(&dir, "alice", 1)).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }
}
