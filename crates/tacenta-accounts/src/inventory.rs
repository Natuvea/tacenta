//! Durable per-account device inventory state.
//!
//! This module deliberately records lifecycle state without signing it or
//! publishing it. The hosted issuer is a server concern: it authorizes a
//! mutation, commits this record, then signs the canonical statement and
//! repairs directory publication if necessary.

use crate::protocol::{put_u32, put_u64};
#[cfg(feature = "postgres")]
use crate::protocol::{take_u32, take_u64};
use tacenta_core::crypto::groups::inventory::{DeviceBinding, InventoryStatement, Revocation};
#[cfg(feature = "postgres")]
use tacenta_core::crypto::groups::inventory::{MAX_ACTIVE_BINDINGS, MAX_RECENT_REVOCATIONS};

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
    /// An idempotency key was reused for a different mutation request.
    IdempotencyConflict,
    /// The proposed record violates the canonical inventory bounds.
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InventoryMutation {
    pub predecessor_generation: u64,
    pub binding: DeviceBinding,
    pub result: DeviceInventory,
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

pub(crate) fn encode_inventory(inventory: &DeviceInventory) -> Vec<u8> {
    let mut out = Vec::new();
    put_u64(&mut out, inventory.generation);
    put_u32(&mut out, inventory.active.len() as u32);
    for binding in &inventory.active {
        put_binding(&mut out, binding);
    }
    put_u64(&mut out, inventory.revocation_floor_generation);
    put_u32(&mut out, inventory.revoked.len() as u32);
    for revocation in &inventory.revoked {
        put_binding(&mut out, &revocation.binding);
        put_u64(&mut out, revocation.terminal_generation);
    }
    out
}

#[cfg(feature = "postgres")]
pub(crate) fn decode_inventory(bytes: &[u8]) -> Option<DeviceInventory> {
    let (generation, mut rest) = take_u64(bytes)?;
    let (active_count, r) = take_u32(rest)?;
    if active_count as usize > MAX_ACTIVE_BINDINGS {
        return None;
    }
    rest = r;
    let mut active = Vec::new();
    for _ in 0..active_count {
        let (binding, r) = take_binding(rest)?;
        active.push(binding);
        rest = r;
    }
    let (revocation_floor_generation, r) = take_u64(rest)?;
    rest = r;
    let (revoked_count, r) = take_u32(rest)?;
    if revoked_count as usize > MAX_RECENT_REVOCATIONS {
        return None;
    }
    rest = r;
    let mut revoked = Vec::new();
    for _ in 0..revoked_count {
        let (binding, r) = take_binding(rest)?;
        let (terminal_generation, r) = take_u64(r)?;
        revoked.push(Revocation {
            binding,
            terminal_generation,
        });
        rest = r;
    }
    rest.is_empty().then_some(DeviceInventory {
        generation,
        active,
        revocation_floor_generation,
        revoked,
    })
}

pub(crate) fn link_inventory(
    account_handle: &str,
    current: &DeviceInventory,
    predecessor_generation: u64,
    binding: DeviceBinding,
) -> Result<DeviceInventory, InventoryError> {
    if current.generation != predecessor_generation {
        return Err(InventoryError::PredecessorMismatch);
    }
    if current.active.iter().any(|existing| existing == &binding) {
        return Err(InventoryError::DuplicateBinding);
    }
    if current
        .active
        .iter()
        .any(|existing| existing.device_id == binding.device_id)
    {
        return Err(InventoryError::DeviceIdInUse);
    }
    if current
        .revoked
        .iter()
        .any(|revoked| revoked.binding == binding)
    {
        return Err(InventoryError::BindingRevoked);
    }

    let mut next = current.clone();
    next.generation = next
        .generation
        .checked_add(1)
        .ok_or(InventoryError::GenerationExhausted)?;
    next.active.push(binding);
    next.active.sort();
    validate_inventory(account_handle, &next)?;
    Ok(next)
}

#[cfg(feature = "postgres")]
pub(crate) fn encode_link_request(predecessor_generation: u64, binding: &DeviceBinding) -> Vec<u8> {
    let mut out = predecessor_generation.to_be_bytes().to_vec();
    put_binding(&mut out, binding);
    out
}

#[cfg(feature = "postgres")]
pub(crate) fn decode_link_request(bytes: &[u8]) -> Option<(u64, DeviceBinding)> {
    let (predecessor_generation, rest) = take_u64(bytes)?;
    let (binding, rest) = take_binding(rest)?;
    rest.is_empty().then_some((predecessor_generation, binding))
}

fn put_binding(out: &mut Vec<u8>, binding: &DeviceBinding) {
    put_u32(out, binding.device_id);
    out.extend_from_slice(&binding.identity_public_key);
    put_u64(out, binding.capabilities);
    match binding.replacement_predecessor {
        Some(predecessor) => {
            out.push(1);
            out.extend_from_slice(&predecessor);
        }
        None => out.push(0),
    }
}

#[cfg(feature = "postgres")]
fn take_binding(bytes: &[u8]) -> Option<(DeviceBinding, &[u8])> {
    let (device_id, rest) = take_u32(bytes)?;
    let (identity_public_key, rest) = rest.split_at_checked(32)?;
    let (capabilities, rest) = take_u64(rest)?;
    let (present, rest) = rest.split_first()?;
    let (replacement_predecessor, rest) = match present {
        0 => (None, rest),
        1 => {
            let (key, rest) = rest.split_at_checked(32)?;
            (Some(key.try_into().ok()?), rest)
        }
        _ => return None,
    };
    Some((
        DeviceBinding {
            device_id,
            identity_public_key: identity_public_key.try_into().ok()?,
            capabilities,
            replacement_predecessor,
        },
        rest,
    ))
}
