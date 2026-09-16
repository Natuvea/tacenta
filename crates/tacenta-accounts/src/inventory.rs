//! Durable per-account device inventory state.
//!
//! This module deliberately records lifecycle state without signing it or
//! publishing it. The hosted issuer is a server concern: it authorizes a
//! mutation, commits this record, then signs the canonical statement and
//! repairs directory publication if necessary.

use tacenta_core::crypto::groups::inventory::{DeviceBinding, InventoryStatement, Revocation};

/// The lifecycle state from which the hosted issuer creates one canonical
/// inventory statement. A missing record for an existing account is this
/// empty state at generation zero.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct DeviceInventory {
    pub generation: u64,
    pub active: Vec<DeviceBinding>,
    pub revocation_floor_generation: u64,
    pub revoked: Vec<Revocation>,
}

/// Why a durable inventory mutation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InventoryError {
    /// The `(tenant, username)` does not name an existing account.
    UnknownUser,
    /// The caller did not name the inventory generation it is replacing.
    PredecessorMismatch,
    /// The generation counter cannot advance any further.
    GenerationExhausted,
    /// The exact binding is already active.
    DuplicateBinding,
    /// A different active binding already occupies this directory device id.
    DeviceIdInUse,
    /// A revoked binding may not silently become active again.
    BindingRevoked,
    /// The proposed record violates the canonical inventory bounds.
    Invalid,
}

pub(crate) fn validate_inventory(
    account_handle: &str,
    inventory: &DeviceInventory,
) -> Result<(), InventoryError> {
    // The core owns all byte-level bounds and canonical ordering requirements.
    // issuer_key_id is irrelevant to durable lifecycle state, so a fixed value
    // is sufficient to exercise exactly that validation surface.
    InventoryStatement {
        issuer_key_id: 0,
        account_handle: account_handle.to_owned(),
        inventory_generation: inventory.generation,
        active: inventory.active.clone(),
        revocation_floor_generation: inventory.revocation_floor_generation,
        revoked: inventory.revoked.clone(),
    }
    .encode_unsigned()
    .map(|_| ())
    .map_err(|_| InventoryError::Invalid)
}
