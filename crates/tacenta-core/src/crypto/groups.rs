//! The product-facing route to standalone bounded group commitments.
//!
//! Product code supplies already canonical roster or application-context bytes.
//! Parsing, identity binding, and membership policy stay outside this adapter.

/// Computes the standalone core's domain-separated commitment of a canonical
/// bounded group roster preimage.
pub fn roster_commitment(preimage: &[u8]) -> [u8; 32] {
    open_tacenta::groups::roster_commitment(preimage)
}

/// Computes the standalone core's domain-separated commitment of a canonical
/// bounded group application context.
pub fn payload_commitment(context: &[u8]) -> [u8; 32] {
    open_tacenta::groups::payload_commitment(context)
}

/// Canonical hosted device-inventory statements. The standalone core owns the
/// encoding and issuer-signature verification; product services own account
/// authorization, durable lifecycle state, and directory publication.
pub mod inventory {
    pub use open_tacenta::groups::inventory::{
        DeviceBinding, Error, GROUP_EPOCH_V1, INVENTORY_DOMAIN, InventoryStatement,
        MAX_ACCOUNT_BYTES, MAX_ACTIVE_BINDINGS, MAX_RECENT_REVOCATIONS, Revocation,
    };
}

#[cfg(test)]
mod tests {
    use super::{payload_commitment, roster_commitment};

    #[test]
    fn the_adapter_uses_distinct_core_domains() {
        assert_ne!(
            roster_commitment(b"same canonical value"),
            payload_commitment(b"same canonical value")
        );
    }
}
