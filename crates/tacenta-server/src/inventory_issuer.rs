//! The deployment-held signer for hosted account device inventories.
//!
//! Its file is deliberately separate from account snapshots and database rows:
//! those records describe devices, while this key attests to them. A deployment
//! distributes [`public_key`](InventoryIssuer::public_key) and its key id to
//! clients through configured service metadata; it never derives a new issuer
//! identity from account or device material.
//!
//! # The key file
//!
//! [`InventoryIssuer::load_or_create`] keeps the signing secret in one small
//! file and treats that file as the trust anchor:
//!
//! * **Created owner-only, from the first byte.** The secret is written to a
//!   uniquely named temporary file that is created with mode `0600`
//!   (`O_EXCL`, so a pre-planted file or symlink is never opened), flushed, and
//!   then published under its final name with a hard link. No file holding the
//!   secret has ever been readable by another user, and the final name never
//!   shows a partly written key.
//! * **Created once.** The publish fails if the name exists, so when two
//!   processes start together the loser reads the winner's key instead of
//!   replacing it: every starter serves the same issuer.
//! * **Refused if others can read it.** An existing file with any group or
//!   other permission bit set is refused (`PermissionDenied`) rather than used
//!   or quietly repaired, because a key that was readable may have been copied.
//!   Fix the mode (`chmod 600`) or rotate the key deliberately.
//!
//! **Windows.** None of the mode handling exists there: the standard library
//! has no portable way to set an access-control list, so the file inherits the
//! ACL of its directory and no permission check runs on load. A Windows
//! deployment must place the key in a directory that only the service account
//! can read; this code does not enforce that. Publishing needs a file system
//! that supports hard links (the creation fails, without a key, on one that does
//! not).

use std::io::Write as _;
use std::path::{Path, PathBuf};

use rand::{CryptoRng as RandCryptoRng, RngCore as RandRngCore, TryRngCore as _};
use tacenta_accounts::DeviceInventory;
use tacenta_core::crypto::groups::inventory::{
    Error as InventoryCodecError, InventoryStatement, issuer_public_key,
};
use zeroize::Zeroizing;

const ISSUER_FILE_MAGIC: &[u8] = b"TCIV\x01";

/// `open-tacenta`'s statement signer still takes the rand_core 0.6 traits,
/// while this product uses rand 0.9. Forward its deployment CSPRNG byte for
/// byte, as the product crypto provider does for session operations.
struct RngBridge<R>(R);

impl<R: RandRngCore> rand_core_06::RngCore for RngBridge<R> {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.0.fill_bytes(dest);
        Ok(())
    }
}

impl<R: RandRngCore + RandCryptoRng> rand_core_06::CryptoRng for RngBridge<R> {}

/// A distinct deployment signer for canonical inventory statements.
pub struct InventoryIssuer {
    key_id: u64,
    secret: Zeroizing<[u8; 32]>,
}

impl InventoryIssuer {
    /// Construct an issuer from deployment-managed secret material.
    pub fn from_secret(key_id: u64, secret: [u8; 32]) -> InventoryIssuer {
        InventoryIssuer {
            key_id,
            secret: Zeroizing::new(secret),
        }
    }

    /// Load the isolated issuer key, creating it atomically only on first
    /// startup. A changed configured key id refuses the existing file rather
    /// than silently rotating the trust anchor.
    ///
    /// A new file is created owner-only (`0600` on Unix) without any window in
    /// which it is wider, and at most one starter creates it: a concurrent
    /// starter that loses the race loads the winner's key. An existing file
    /// that group or others can access is refused with `PermissionDenied`. See
    /// the [module documentation](self) for the details and for what is not
    /// enforced on Windows.
    pub fn load_or_create(path: &Path, key_id: u64) -> std::io::Result<InventoryIssuer> {
        match read_key_file(path) {
            Ok(bytes) => Self::decode_file(&bytes, key_id),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut secret = Zeroizing::new([0u8; 32]);
                rand::rngs::OsRng.unwrap_err().fill_bytes(&mut *secret);
                let issuer = Self::from_secret(key_id, *secret);
                match create_key_file(path, &issuer.encode_file()) {
                    Ok(()) => Ok(issuer),
                    // Another starter published first. Serve its key, not ours.
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        Self::decode_file(&read_key_file(path)?, key_id)
                    }
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    }

    /// The configured issuer key id included in every statement.
    pub fn key_id(&self) -> u64 {
        self.key_id
    }

    /// The public key clients pin alongside [`key_id`](InventoryIssuer::key_id).
    pub fn public_key(&self) -> [u8; 32] {
        issuer_public_key(&self.secret)
    }

    /// Sign the exact canonical statement for one committed account inventory.
    pub fn issue(
        &self,
        account_handle: String,
        inventory: DeviceInventory,
    ) -> Result<Vec<u8>, InventoryCodecError> {
        let mut rng = RngBridge(rand::rngs::OsRng.unwrap_err());
        InventoryStatement {
            issuer_key_id: self.key_id,
            account_handle,
            inventory_generation: inventory.generation,
            active: inventory.active,
            revocation_floor_generation: inventory.revocation_floor_generation,
            revoked: inventory.revoked,
        }
        .encode_signed(&self.secret, &mut rng)
    }

    fn encode_file(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(ISSUER_FILE_MAGIC.to_vec());
        bytes.extend_from_slice(&self.key_id.to_be_bytes());
        bytes.extend_from_slice(&*self.secret);
        bytes
    }

    fn decode_file(bytes: &[u8], configured_key_id: u64) -> std::io::Result<InventoryIssuer> {
        let expected_len = ISSUER_FILE_MAGIC.len() + 8 + 32;
        if bytes.len() != expected_len || !bytes.starts_with(ISSUER_FILE_MAGIC) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "malformed inventory issuer key file",
            ));
        }
        let key_start = ISSUER_FILE_MAGIC.len();
        let key_id = u64::from_be_bytes(
            bytes[key_start..key_start + 8]
                .try_into()
                .expect("length checked"),
        );
        if key_id != configured_key_id {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "inventory issuer key id does not match deployment configuration",
            ));
        }
        let secret = bytes[key_start + 8..].try_into().expect("length checked");
        Ok(InventoryIssuer::from_secret(key_id, secret))
    }
}

/// Read the key file, refusing one that group or others can access.
///
/// The mode is read from the open descriptor, not from the path, so it is the
/// mode of the file actually read.
fn read_key_file(path: &Path) -> std::io::Result<Zeroizing<Vec<u8>>> {
    use std::io::Read as _;
    let mut file = std::fs::File::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = file.metadata()?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "inventory issuer key file is accessible to group or others (mode {mode:o}); \
                     it must be owner-only (chmod 600), or the key rotated if it may have been read"
                ),
            ));
        }
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Publish `bytes` at `path` only if nothing is there, owner-only from the
/// first byte. `Err(AlreadyExists)` means another starter published first.
fn create_key_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut staging = path.as_os_str().to_owned();
    staging.push(format!(
        ".{}.{:016x}.tmp",
        std::process::id(),
        rand::rngs::OsRng.unwrap_err().next_u64()
    ));
    publish_key_file(path, &PathBuf::from(staging), bytes)
}

/// [`create_key_file`] with the staging name given, so a test can plant
/// something at exactly the name that will be opened. The name is chosen at
/// random in production and nothing else depends on it.
///
/// The secret is first written under `staging`, which must not exist:
/// `create_new` is `O_EXCL`, so a file or symlink already there is never opened,
/// written through, or removed. Only a staging file this call created is
/// removed.
fn publish_key_file(path: &Path, staging: &Path, bytes: &[u8]) -> std::io::Result<()> {
    // `create_new` is `O_EXCL`: it never opens an existing file and never
    // follows a symlink at the staging name.
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(staging)?;
    // From here the staging file is ours, and is dropped whatever happens.
    let published = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        // `link` fails with `AlreadyExists` rather than replacing, and makes
        // the complete file appear under its final name in one step.
        std::fs::hard_link(staging, path)
    })();
    let _ = std::fs::remove_file(staging);
    published?;
    #[cfg(unix)]
    if let Some(directory) = path.parent() {
        let directory = if directory.as_os_str().is_empty() {
            Path::new(".")
        } else {
            directory
        };
        std::fs::File::open(directory)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::InventoryIssuer;
    use tacenta_accounts::DeviceInventory;
    use tacenta_core::crypto::groups::inventory::InventoryStatement;

    fn issuer_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "tacenta-inventory-issuer-{}",
            rand::random::<u64>()
        ))
    }

    #[test]
    fn issuer_signs_with_a_distinct_pinned_public_key() {
        let issuer = InventoryIssuer::from_secret(7, [9; 32]);
        let signed = issuer
            .issue("acme/alice".into(), DeviceInventory::default())
            .unwrap();
        let decoded = InventoryStatement::decode_signed(&signed, &issuer.public_key()).unwrap();
        assert_eq!(decoded.issuer_key_id, 7);
        assert_eq!(decoded.account_handle, "acme/alice");
    }

    #[test]
    fn issuer_key_file_is_stable_and_rejects_an_unexpected_key_id() {
        let path = issuer_path();
        let first = InventoryIssuer::load_or_create(&path, 7).unwrap();
        let public = first.public_key();
        drop(first);

        let loaded = InventoryIssuer::load_or_create(&path, 7).unwrap();
        assert_eq!(loaded.public_key(), public, "restart keeps the pinned key");
        assert!(InventoryIssuer::load_or_create(&path, 8).is_err());
        std::fs::remove_file(path).ok();
    }

    /// A private directory for one test, removed on drop.
    struct TestDir(std::path::PathBuf);

    impl TestDir {
        fn new() -> TestDir {
            let dir = std::env::temp_dir().join(format!(
                "tacenta-inventory-issuer-dir-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir(&dir).unwrap();
            TestDir(dir)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    #[cfg(unix)]
    fn mode_of(path: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// The signing key is created owner-only. A creation that used the
    /// process umask would leave it 0644, readable by every local user.
    #[cfg(unix)]
    #[test]
    fn a_new_issuer_key_file_is_owner_only() {
        let dir = TestDir::new();
        let path = dir.path().join("issuer.key");
        InventoryIssuer::load_or_create(&path, 7).unwrap();
        assert_eq!(mode_of(&path), 0o600);
    }

    /// The bytes are never in a file wider than owner-only, not even
    /// transiently: the temporary file is created 0600 too, so a reader
    /// cannot open it between the write and the publish. The scan below looks
    /// for any file the creation leaves behind in the directory.
    #[cfg(unix)]
    #[test]
    fn creation_leaves_no_temporary_file_and_nothing_wider_than_owner_only() {
        let dir = TestDir::new();
        let path = dir.path().join("issuer.key");
        InventoryIssuer::load_or_create(&path, 7).unwrap();
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let entry = entry.unwrap();
            assert_eq!(entry.path(), path, "unexpected leftover {:?}", entry.path());
            assert_eq!(mode_of(&entry.path()) & 0o077, 0);
        }
    }

    /// The staging name is random, so `load_or_create` cannot be made to open a
    /// name a test has planted. [`publish_key_file`] takes the name, and these two
    /// tests plant at exactly that name. Without `O_EXCL` (`create_new`) the first
    /// writes the secret through the symlink into the victim file and the second
    /// overwrites the planted file; each fails then.
    #[cfg(unix)]
    #[test]
    fn a_symlink_planted_at_the_staging_name_is_not_written_through() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new();
        let path = dir.path().join("issuer.key");
        let staging = dir.path().join("issuer.key.staging");
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"not a key").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::os::unix::fs::symlink(&victim, &staging).unwrap();

        let error = super::publish_key_file(&path, &staging, b"the secret bytes")
            .expect_err("a staging name that exists is refused");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);

        assert_eq!(std::fs::read(&victim).unwrap(), b"not a key");
        assert_eq!(mode_of(&victim), 0o644);
        assert!(!path.exists(), "no key was published");
        assert!(
            std::fs::symlink_metadata(&staging)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the planted link is left as it was, not followed and not removed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_regular_file_planted_at_the_staging_name_is_not_reused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new();
        let path = dir.path().join("issuer.key");
        let staging = dir.path().join("issuer.key.staging");
        std::fs::write(&staging, b"planted").unwrap();
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o644)).unwrap();

        let error = super::publish_key_file(&path, &staging, b"the secret bytes")
            .expect_err("a staging name that exists is refused");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);

        assert_eq!(
            std::fs::read(&staging).unwrap(),
            b"planted",
            "the secret was not written into a file someone else made"
        );
        assert_eq!(mode_of(&staging), 0o644, "and its mode was not touched");
        assert!(!path.exists(), "no key was published");
    }

    /// A publish puts the bytes, owner-only, at the final name and leaves no
    /// staging file. A second one finds the name taken and changes nothing.
    #[cfg(unix)]
    #[test]
    fn publishing_moves_the_bytes_to_the_final_name_owner_only_and_leaves_no_staging_file() {
        let dir = TestDir::new();
        let path = dir.path().join("issuer.key");
        let staging = dir.path().join("issuer.key.staging");
        super::publish_key_file(&path, &staging, b"the secret bytes").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"the secret bytes");
        assert_eq!(mode_of(&path), 0o600);
        assert!(!staging.exists());
        // A second publish finds the name taken and changes nothing.
        let error =
            super::publish_key_file(&path, &staging, b"another secret").expect_err("name is taken");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&path).unwrap(), b"the secret bytes");
        assert!(!staging.exists(), "the staging file this call made is gone");
    }

    /// A key file another user could read is refused rather than trusted or
    /// silently repaired: it may already have been copied.
    #[cfg(unix)]
    #[test]
    fn an_existing_key_file_readable_by_others_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new();
        let path = dir.path().join("issuer.key");
        InventoryIssuer::load_or_create(&path, 7).unwrap();
        for wide in [0o640, 0o604, 0o610, 0o644, 0o666, 0o777] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(wide)).unwrap();
            let error = InventoryIssuer::load_or_create(&path, 7)
                .err()
                .unwrap_or_else(|| panic!("mode {wide:o} was accepted"));
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        }
        for private in [0o400, 0o600, 0o700] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(private)).unwrap();
            InventoryIssuer::load_or_create(&path, 7)
                .unwrap_or_else(|e| panic!("owner-only mode {private:o} was refused: {e}"));
        }
    }

    /// Two processes starting at once must end up with one issuer key, not one
    /// each with the last rename winning. Threads stand in for processes: the
    /// creation path is the same and the file system arbitrates.
    #[test]
    fn concurrent_first_starts_agree_on_one_key() {
        for round in 0..20 {
            let dir = TestDir::new();
            let path = dir.path().join("issuer.key");
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let (path, barrier) = (path.clone(), barrier.clone());
                    std::thread::spawn(move || {
                        barrier.wait();
                        InventoryIssuer::load_or_create(&path, 7)
                            .expect("every starter gets a key")
                            .public_key()
                    })
                })
                .collect();
            let keys: Vec<[u8; 32]> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            assert!(
                keys.iter().all(|key| key == &keys[0]),
                "round {round}: starters disagree on the issuer key"
            );
            let reloaded = InventoryIssuer::load_or_create(&path, 7).unwrap();
            assert_eq!(reloaded.public_key(), keys[0]);
        }
    }
}
