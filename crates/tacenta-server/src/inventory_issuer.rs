//! The deployment-held signer for hosted account device inventories.
//!
//! Its file is deliberately separate from account snapshots and database rows:
//! those records describe devices, while this key attests to them. A deployment
//! distributes [`public_key`](InventoryIssuer::public_key) and its key id to
//! clients through configured service metadata; it never derives a new issuer
//! identity from account or device material.

use std::path::Path;

use rand::{CryptoRng as RandCryptoRng, RngCore as RandRngCore, TryRngCore as _};
use tacenta_accounts::DeviceInventory;
use tacenta_core::crypto::groups::inventory::{
    Error as InventoryCodecError, InventoryStatement, issuer_public_key,
};
use tacenta_core::persist::write_atomically;
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
    pub fn load_or_create(path: &Path, key_id: u64) -> std::io::Result<InventoryIssuer> {
        match std::fs::read(path) {
            Ok(bytes) => Self::decode_file(&bytes, key_id),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut secret = [0u8; 32];
                rand::rngs::OsRng.unwrap_err().fill_bytes(&mut secret);
                let issuer = Self::from_secret(key_id, secret);
                write_atomically(path, &issuer.encode_file())?;
                Ok(issuer)
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

    fn encode_file(&self) -> Vec<u8> {
        let mut bytes = ISSUER_FILE_MAGIC.to_vec();
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
}
