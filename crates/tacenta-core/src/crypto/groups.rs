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
        DeviceBinding, Error, GROUP_EPOCH_V1, INVENTORY_DOMAIN, InventoryStatement,
        MAX_ACCOUNT_BYTES, MAX_ACTIVE_BINDINGS, MAX_RECENT_REVOCATIONS, Revocation,
    };
}
