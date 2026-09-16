//! The product-facing route to the standalone core's group helpers.
//!
//! This branch carries only the hosted device-inventory statements; the
//! bounded group commitments live on the group branch and join this file when
//! the two land.

/// Canonical hosted device-inventory statements. The standalone core owns the
/// encoding and issuer-signature verification; product services own account
/// authorization, durable lifecycle state, and directory publication.
pub mod inventory {
    pub use open_tacenta::groups::inventory::{
        BINDING_COMMITMENT_LABEL, DeviceBinding, Error, GROUP_EPOCH_V1, INVENTORY_DOMAIN,
        InventoryStatement, MAX_ACCOUNT_BYTES, MAX_ACTIVE_BINDINGS, MAX_RECENT_REVOCATIONS,
        Revocation,
    };

    /// Commit the exact canonical binding a replacement retires.
    pub fn binding_commitment(binding: &DeviceBinding) -> Result<[u8; 32], Error> {
        open_tacenta::groups::inventory::binding_commitment(binding)
    }

    /// Derive the pinned public key corresponding to a deployment-held issuer
    /// secret. The secret stays with the service; callers distribute only this
    /// 32-byte value and its configured key identifier to clients.
    pub fn issuer_public_key(issuer_secret: &[u8; 32]) -> [u8; 32] {
        open_tacenta::primitives::dh::PrivateKey::from_bytes(*issuer_secret)
            .public_key()
            .as_bytes()
            .to_owned()
    }
}
