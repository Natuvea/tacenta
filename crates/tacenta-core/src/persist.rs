//! Writing bytes to a file so that a crash cannot lose or tear them.
//!
//! **Why this is a public utility and not a private detail of one type.**
//! Decision 0077 makes the exported blob the persistence contract:
//! `Client::export_state` hands the caller bytes and the caller decides where
//! they live. That leaves every caller to rediscover the crash-safe write, and
//! most will reach for `fs::write`, which can tear and is not durable when it
//! returns.
//!
//! The sequence lives here, over a path and a slice, rather than inside
//! `DurableOpenParty` (a type the SDK's own client cannot construct), because
//! the write is orthogonal to whatever produced the bytes and every caller
//! has to be able to reach it.
//!
//! **Decision 0078 attaches the rollback anchor here**, for the same reason:
//! so that an anchor can sit on every caller's path rather than inside one
//! provider.
//!
//! **These are 0078's anchor B, reachable on the sealed path.** `seal`/`unseal`
//! below authenticate a generation into the bytes;
//! `tacenta_client::Client::export_state_sealed` calls `seal`, and
//! `connect_with_state_sealed` / `sign_in_with_state_sealed` call `unseal`,
//! refusing a state whose authenticator does not verify. `freshness` is a
//! statement of decisions 3/3a as a function; the running freshness check is
//! the directory's `witness_core`, which the sealed restore reaches through
//! `Client::checkpoint`.
//!
//! **The key is the seam.** 0078 puts the wrapping key in platform secure
//! storage; the client takes it through a `SecureStore` trait, so
//! `seal`/`unseal` authenticate under whatever the platform binding supplies.
//! The iOS Keychain / Android Keystore implementations of that trait are still
//! to be written — until they are, the FFI ships the unsealed path — but the
//! *authenticator* is wired and tested (under a mock key).
//!
//! **Anchor A alone is detection, not the full closure — and B is why.** The
//! directory witnesses a monotone generation (`tacenta-directory`,
//! `Directory::witness`) and the client presents it (`Client::checkpoint`), so
//! a restore of an *unmodified* older state — a legitimate backup, or a naive
//! whole-file replay — is caught and answered by discarding sessions (decision
//! 3). But on the **unsealed** path the generation the client presents is
//! *these very bytes* as plaintext: an attacker who can rewrite the file
//! (the rollback threat) sets the generation high and A reports Fresh. The
//! **sealed** path closes that — the generation is authenticated, so the
//! forgery breaks the seal and the restore is refused — and a `SecureStore`
//! rollback counter additionally catches an older *saved* state. Together they
//! narrow the rollback gap sharply, but do not fully close it: the per-send
//! window remains (`docs/decisions/0078`).

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// Write `bytes` to `path` so that a crash leaves `path` holding either its
/// previous complete contents or these new complete contents, never a mix, and
/// so that a successful return means the new contents survive a power loss.
///
/// **Those are two separate guarantees and it is worth keeping them apart.**
///
/// *Atomicity*: a temp file in the same directory, written and `fsync`ed, then
/// renamed over the target. `rename` is atomic on a filesystem, so the target
/// is never observed half-written. This is what the fault-injection tests
/// exercise, by simulating a crash between the write and the rename.
///
/// *Durability after return*: the containing directory is then `fsync`ed too. A
/// rename is a directory modification and is not on disk until the directory
/// is flushed. Without that step this function could return, the caller could
/// treat the mutation as committed -- advance a ratchet, drop a one-time
/// prekey -- and a power loss could still leave the directory entry pointing at
/// the old file. Atomicity would have held; durability would not.
///
/// The tests below are split the same way: the fault-injection test covers
/// the first guarantee, and a separate test covers the mechanism of the
/// second.
pub fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp_path = PathBuf::from(tmp);
    {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;
    fsync_parent_dir(path)?;
    Ok(())
}

/// Flush the directory entry a rename created.
///
/// Named rather than inlined so a test can reach it. **What a test can and
/// cannot show is worth stating**: that this succeeds on a real directory and
/// reports failure rather than swallowing it is testable in process; that the
/// entry survives a power loss is not, because nothing in userspace can cut the
/// power. The fsync is the mechanism, and the mechanism is what is covered.
fn fsync_parent_dir(path: &Path) -> io::Result<()> {
    let Some(dir) = path.parent() else {
        // No parent means the rename could not have succeeded, so this is
        // unreachable in practice.
        return Ok(());
    };
    // An empty parent is `.`, which `File::open` handles; a directory opened
    // read-only can still be synced.
    let dir = if dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        dir
    };
    fs::File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "tacenta-persist-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn it_creates_and_then_fully_replaces() {
        let dir = tempdir();
        let path = dir.join("f.bin");
        write_atomically(&path, b"one").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"one");
        write_atomically(&path, b"two-and-longer").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"two-and-longer");
        fs::remove_dir_all(&dir).ok();
    }

    /// A crash between the temp write and the rename must not disturb the
    /// target. This is the *atomicity* half.
    #[test]
    fn a_stray_temp_file_does_not_disturb_the_target() {
        let dir = tempdir();
        let path = dir.join("f.bin");
        write_atomically(&path, b"committed").unwrap();

        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        fs::write(PathBuf::from(tmp), b"never renamed").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"committed");
        write_atomically(&path, b"next").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"next");
        fs::remove_dir_all(&dir).ok();
    }

    /// The *durability* half, as far as a process can check it: the parent sync
    /// runs, and it reports failure rather than swallowing it. It does not
    /// prove the entry survives a power loss, and no in-process test can.
    #[test]
    fn the_parent_directory_sync_runs_and_reports_failure() {
        let dir = tempdir();
        let path = dir.join("f.bin");
        write_atomically(&path, b"one").unwrap();
        fsync_parent_dir(&path).unwrap();

        let gone = dir.join("no-such-dir").join("f.bin");
        assert!(
            fsync_parent_dir(&gone).is_err(),
            "a missing parent must be reported, not ignored"
        );
        fs::remove_dir_all(&dir).ok();
    }
}

// ---------------------------------------------------------------- the anchor
//
// Decision 0078's local half. The server-side generation witness is not here:
// it travels on the authenticated directory path, so it belongs to that
// frame's authentication rather than to a new field here.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// This envelope's own format version, separate from any version inside the
/// bytes it wraps.
const SEAL_VERSION: u8 = 0x01;
const GENERATION_LEN: usize = 8;
const TAG_LEN: usize = 32;
const SEAL_OVERHEAD: usize = 1 + GENERATION_LEN + TAG_LEN;

/// The label this envelope's authenticator is derived under.
///
/// Follows the scheme tacenta-core's `tacenta-core/LABELS.md` sets for new labels: a
/// `tacenta:` prefix, `:` as the only separator, a version segment, and a
/// terminator byte that cannot occur in the prefix, which makes prefix-freedom
/// structural rather than something to check.
const SEAL_LABEL: &[u8] = b"tacenta:persisted-state:v1\xff";

/// Why a sealed blob was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SealError {
    /// Not this envelope format, or a version this build does not know.
    UnknownVersion,
    /// Too short to contain a version, a generation and a tag.
    TooShort,
    /// The authenticator does not match. **The bytes were altered, or the key
    /// is wrong, and this cannot tell you which** -- deliberately, because
    /// saying which is a decryption oracle in miniature.
    BadAuthenticator,
}

/// What came out of a blob that authenticated.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Unsealed {
    /// The generation the writer stamped. Authenticated, so an attacker cannot
    /// lower it without breaking the tag.
    pub generation: u64,
    pub payload: Vec<u8>,
}

/// Wrap `payload` with a generation counter and an authenticator.
///
/// **The generation is the point.** A MAC alone gives integrity and not
/// freshness: an attacker who can write the file can write an earlier, validly
/// authenticated file, and every byte checks out. Binding a counter into the
/// authenticated bytes is what lets a reader notice that the state it is
/// holding is older than one it has seen before.
///
/// `key` belongs in platform secure storage -- Keychain, Android Keystore, or
/// equivalent -- and **not beside the blob**. An attacker who can rewrite the
/// file and the key has defeated this; the whole construction rests on those
/// two living in different places.
///
/// The payload is authenticated, not encrypted. At-rest confidentiality is a
/// separate boundary, stated in tacenta-core's
/// `tacenta-spec/protocol/key-deletion.md` as the
/// caller's job, and widening it here would be a decision rather than an
/// implementation detail.
pub fn seal(key: &[u8; 32], generation: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SEAL_OVERHEAD + payload.len());
    out.push(SEAL_VERSION);
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(payload);
    let tag = tag_over(key, &out);
    out.extend_from_slice(&tag);
    out
}

/// Verify and open a blob produced by [`seal`].
pub fn unseal(key: &[u8; 32], sealed: &[u8]) -> Result<Unsealed, SealError> {
    if sealed.len() < SEAL_OVERHEAD {
        return Err(SealError::TooShort);
    }
    if sealed[0] != SEAL_VERSION {
        return Err(SealError::UnknownVersion);
    }
    let (body, tag) = sealed.split_at(sealed.len() - TAG_LEN);

    // Constant-time, through the Mac machinery rather than a byte comparison.
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(SEAL_LABEL);
    m.update(body);
    m.verify_slice(tag)
        .map_err(|_| SealError::BadAuthenticator)?;

    let mut gen_bytes = [0u8; GENERATION_LEN];
    gen_bytes.copy_from_slice(&body[1..1 + GENERATION_LEN]);
    Ok(Unsealed {
        generation: u64::from_be_bytes(gen_bytes),
        payload: body[1 + GENERATION_LEN..].to_vec(),
    })
}

fn tag_over(key: &[u8; 32], body: &[u8]) -> [u8; TAG_LEN] {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(SEAL_LABEL);
    m.update(body);
    let out = m.finalize().into_bytes();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&out);
    tag
}

/// What a reader should do with state whose generation it has just learned.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Freshness {
    /// At or ahead of anything seen before. Resume normally.
    Current,
    /// Older than a generation already seen. **Decision 0078: load it, keep the
    /// identity, and discard every session rather than resuming a ratchet.**
    ///
    /// Rollback and a legitimate backup restore are indistinguishable from
    /// outside -- the same bytes, the same action -- so refusing would break
    /// restore and resuming would be the vulnerability. Discarding sessions is
    /// neither: a fresh session is an ordinary event, so the user gets working
    /// software and an attacker gets a client that has forgotten the chain keys
    /// they wanted replayed.
    RolledBack,
}

/// Compare a generation against the highest previously seen.
///
/// `highest_seen` is whatever the caller has recorded, and under 0078 the
/// authoritative copy of it lives in the directory. **Before the directory has
/// been reached, a caller has no `highest_seen` and should resume** (decision
/// 3a): assuming stale until the witness confirms would discard every session
/// on every offline start, which is a protection users switch off.
pub fn freshness(highest_seen: u64, offered: u64) -> Freshness {
    if offered < highest_seen {
        Freshness::RolledBack
    } else {
        Freshness::Current
    }
}

#[cfg(test)]
mod seal_tests {
    use super::*;

    const KEY: [u8; 32] = [7u8; 32];

    #[test]
    fn a_sealed_blob_opens_to_what_went_in() {
        let sealed = seal(&KEY, 42, b"state bytes");
        let out = unseal(&KEY, &sealed).expect("our own seal must open");
        assert_eq!(out.generation, 42);
        assert_eq!(out.payload, b"state bytes");
    }

    /// **The point of the whole construction.** An attacker who rewrites the
    /// file wants to present an older generation with a payload that still
    /// authenticates. The counter is inside the authenticated bytes, so
    /// lowering it breaks the tag.
    #[test]
    fn the_generation_cannot_be_lowered_without_breaking_the_tag() {
        let sealed = seal(&KEY, 9, b"state bytes");
        let mut rolled = sealed.clone();
        rolled[1..9].copy_from_slice(&1u64.to_be_bytes());
        assert_ne!(rolled, sealed);
        assert_eq!(unseal(&KEY, &rolled), Err(SealError::BadAuthenticator));
    }

    #[test]
    fn every_single_byte_change_is_refused() {
        let sealed = seal(&KEY, 3, b"a payload worth protecting");
        for i in 0..sealed.len() {
            let mut dirty = sealed.clone();
            dirty[i] ^= 0xFF;
            assert!(
                unseal(&KEY, &dirty).is_err(),
                "byte {i} was altered and the blob still opened"
            );
        }
    }

    #[test]
    fn a_different_key_does_not_open_it() {
        let sealed = seal(&KEY, 1, b"x");
        assert_eq!(
            unseal(&[8u8; 32], &sealed),
            Err(SealError::BadAuthenticator)
        );
    }

    #[test]
    fn short_and_foreign_blobs_are_refused_before_the_mac() {
        assert_eq!(unseal(&KEY, b"too short"), Err(SealError::TooShort));
        let mut wrong_version = seal(&KEY, 1, b"x");
        wrong_version[0] = 0xFE;
        assert_eq!(unseal(&KEY, &wrong_version), Err(SealError::UnknownVersion));
    }

    /// Decision 0078's policy, as a function. An equal generation is current,
    /// not rolled back: a client that writes and reads without advancing has
    /// not gone backwards.
    #[test]
    fn freshness_follows_the_policy() {
        assert_eq!(freshness(5, 6), Freshness::Current);
        assert_eq!(freshness(5, 5), Freshness::Current);
        assert_eq!(freshness(5, 4), Freshness::RolledBack);
        // Decision 3a: with nothing seen yet, everything is current.
        assert_eq!(freshness(0, 0), Freshness::Current);
    }
}
