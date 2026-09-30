//! Per-account device inventory state.
//!
//! This module deliberately records lifecycle state without signing it or
//! publishing it. The hosted issuer is a server concern: it authorizes a
//! mutation, commits this record, then signs the canonical statement and
//! repairs directory publication if necessary.
//!
//! The rules here are pure functions shared by both store backends. What makes
//! a committed record durable is the backend: the Postgres store commits it in
//! the database; the in-memory store keeps it in memory until the server writes
//! an account snapshot.

use crate::protocol::{put_u32, put_u64};
#[cfg(any(test, feature = "postgres"))]
use crate::protocol::{take_u32, take_u64};
#[cfg(any(test, feature = "postgres"))]
use tacenta_core::crypto::groups::inventory::MAX_ACTIVE_BINDINGS;
use tacenta_core::crypto::groups::inventory::{
    DeviceBinding, Error as CoreError, InventoryStatement, MAX_RECENT_REVOCATIONS, Revocation,
    binding_commitment, validate_identity_key,
};

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

/// Why an inventory mutation was refused.
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
    /// A revoked binding may not silently become active again, for as long as
    /// its revocation is remembered. Only the `MAX_RECENT_REVOCATIONS` most
    /// recent revocations are kept; an older one is dropped and
    /// `revocation_floor_generation` is raised to its terminal generation, after
    /// which the same binding is accepted as new. The floor in the signed
    /// statement is how a verifier learns that history was dropped.
    BindingRevoked,
    /// A device identifier was previously retired and cannot name a new binding,
    /// under the same bounded memory as [`BindingRevoked`](InventoryError::BindingRevoked).
    DeviceIdRetired,
    /// An identity key was already used by another active or retired binding.
    IdentityKeyInUse,
    /// A replace or revoke operation did not name an exact active binding.
    BindingNotActive,
    /// A replacement did not commit to the exact binding it retires.
    ReplacementPredecessorMismatch,
    /// A plain link named a `replacement_predecessor`. Only a replacement
    /// carries one, and only for the binding it retires in the same step; a
    /// marker on a new binding would be a claim of lineage that this account
    /// never made.
    UnexpectedReplacementPredecessor,
    /// A binding's identity key is not one the specification admits (check 6
    /// of "Accepting a signed statement"). The core's own classification is
    /// carried unchanged. Every verifier refuses a statement that lists such a
    /// key, so it is refused here, before anything is stored or signed.
    IdentityKey(CoreError),
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

/// A non-link lifecycle transition kept separately so existing snapshot
/// records for link retries remain readable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LifecycleRequest {
    Replace {
        predecessor_generation: u64,
        retired: DeviceBinding,
        replacement: DeviceBinding,
    },
    Revoke {
        predecessor_generation: u64,
        retired: DeviceBinding,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LifecycleMutation {
    pub request: LifecycleRequest,
    pub result: DeviceInventory,
}

pub(crate) fn validate_inventory(
    account_handle: &str,
    inventory: &DeviceInventory,
) -> Result<(), InventoryError> {
    // The core owns all byte-level bounds and canonical ordering requirements.
    // issuer_key_id is irrelevant to stored lifecycle state, so a fixed value
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

/// Check 6 for one binding the caller supplied, using the core's own rule.
///
/// The rule admits exactly one spelling of a key, so the byte comparisons in
/// [`binding_is_new`] are sound only for keys that passed it. It therefore
/// runs first, before any comparison against the account's state, and before a
/// binding can reach a stored record or a signature. The function is the
/// core's public `validate_identity_key`, not a copy of it.
fn check_supplied_binding(binding: &DeviceBinding) -> Result<(), InventoryError> {
    validate_identity_key(&binding.identity_public_key).map_err(InventoryError::IdentityKey)
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

#[cfg(any(test, feature = "postgres"))]
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
    check_supplied_binding(&binding)?;
    // A new device has no predecessor. The core does not require a marker to
    // name a listed binding (its custody check needs a verifier's own history),
    // so the only place that can keep a made-up lineage out of a signed
    // statement is the issuer, and a plain link is not a replacement.
    if binding.replacement_predecessor.is_some() {
        return Err(InventoryError::UnexpectedReplacementPredecessor);
    }
    if current.generation != predecessor_generation {
        return Err(InventoryError::PredecessorMismatch);
    }
    if current.active.iter().any(|existing| existing == &binding) {
        return Err(InventoryError::DuplicateBinding);
    }
    binding_is_new(current, &binding)?;

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

/// Terminally revoke one exact active binding at an exact predecessor
/// generation. The caller has already checked the lifecycle authorization and
/// proof required for this operation.
pub(crate) fn revoke_inventory(
    account_handle: &str,
    current: &DeviceInventory,
    predecessor_generation: u64,
    retired: DeviceBinding,
) -> Result<DeviceInventory, InventoryError> {
    check_supplied_binding(&retired)?;
    if current.generation != predecessor_generation {
        return Err(InventoryError::PredecessorMismatch);
    }
    let index = current
        .active
        .iter()
        .position(|binding| binding == &retired)
        .ok_or(InventoryError::BindingNotActive)?;
    let mut next = current.clone();
    next.generation = next
        .generation
        .checked_add(1)
        .ok_or(InventoryError::GenerationExhausted)?;
    next.active.remove(index);
    next.revoked.push(Revocation {
        binding: retired,
        terminal_generation: next.generation,
    });
    compact_revocations(&mut next);
    validate_inventory(account_handle, &next)?;
    Ok(next)
}

/// Atomically retire one exact active binding and activate its committed
/// successor. The replacement predecessor is checked before any state changes.
pub(crate) fn replace_inventory(
    account_handle: &str,
    current: &DeviceInventory,
    predecessor_generation: u64,
    retired: DeviceBinding,
    replacement: DeviceBinding,
) -> Result<DeviceInventory, InventoryError> {
    check_supplied_binding(&retired)?;
    check_supplied_binding(&replacement)?;
    // The marker must be the commitment of the exact binding this call retires:
    // not another device of this account, not a device of another account, not
    // a binding that never existed.
    if replacement.replacement_predecessor
        != Some(binding_commitment(&retired).map_err(|_| InventoryError::Invalid)?)
    {
        return Err(InventoryError::ReplacementPredecessorMismatch);
    }
    let revoked = revoke_inventory(account_handle, current, predecessor_generation, retired)?;
    binding_is_new(&revoked, &replacement)?;
    let mut next = revoked;
    next.active.push(replacement);
    next.active.sort();
    validate_inventory(account_handle, &next)?;
    Ok(next)
}

/// The account-level rules for a binding that is not yet in the inventory.
///
/// Identity keys are compared as bytes. That is sound because every key stored
/// through this module, and the one being added, passed
/// `check_supplied_binding`, which admits exactly one spelling of a key; the
/// core's `InventoryPolicy` says the same of a policy that compares keys in a
/// statement it has accepted. A row or snapshot written by anything else is not
/// covered (decision 0140, "The database is trusted for what is signed").
fn binding_is_new(
    current: &DeviceInventory,
    binding: &DeviceBinding,
) -> Result<(), InventoryError> {
    if current.active.iter().any(|existing| existing == binding) {
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
        .active
        .iter()
        .any(|existing| existing.identity_public_key == binding.identity_public_key)
    {
        return Err(InventoryError::IdentityKeyInUse);
    }
    if current
        .revoked
        .iter()
        .any(|revoked| revoked.binding == *binding)
    {
        return Err(InventoryError::BindingRevoked);
    }
    if current
        .revoked
        .iter()
        .any(|revoked| revoked.binding.device_id == binding.device_id)
    {
        return Err(InventoryError::DeviceIdRetired);
    }
    if current
        .revoked
        .iter()
        .any(|revoked| revoked.binding.identity_public_key == binding.identity_public_key)
    {
        return Err(InventoryError::IdentityKeyInUse);
    }
    Ok(())
}

fn compact_revocations(inventory: &mut DeviceInventory) {
    while inventory.revoked.len() > MAX_RECENT_REVOCATIONS {
        let (oldest, _) = inventory
            .revoked
            .iter()
            .enumerate()
            .min_by_key(|(_, revocation)| revocation.terminal_generation)
            .expect("a nonempty revocation list has an oldest entry");
        let retired = inventory.revoked.remove(oldest);
        inventory.revocation_floor_generation = inventory
            .revocation_floor_generation
            .max(retired.terminal_generation);
    }
    inventory.revoked.sort();
}

#[cfg(any(test, feature = "postgres"))]
pub(crate) fn encode_link_request(predecessor_generation: u64, binding: &DeviceBinding) -> Vec<u8> {
    let mut out = predecessor_generation.to_be_bytes().to_vec();
    put_binding(&mut out, binding);
    out
}

#[cfg(any(test, feature = "postgres"))]
pub(crate) fn encode_revoke_request(
    predecessor_generation: u64,
    retired: &DeviceBinding,
) -> Vec<u8> {
    let mut out = b"TCIL\x01\x02".to_vec();
    put_u64(&mut out, predecessor_generation);
    put_binding(&mut out, retired);
    out
}

#[cfg(any(test, feature = "postgres"))]
pub(crate) fn encode_replace_request(
    predecessor_generation: u64,
    retired: &DeviceBinding,
    replacement: &DeviceBinding,
) -> Vec<u8> {
    let mut out = b"TCIL\x01\x01".to_vec();
    put_u64(&mut out, predecessor_generation);
    put_binding(&mut out, retired);
    put_binding(&mut out, replacement);
    out
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

#[cfg(any(test, feature = "postgres"))]
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

#[cfg(test)]
mod codec_tests {
    //! The byte codecs the Postgres store persists, exercised without a
    //! database. A stored row is decoded and validated on every read, so a
    //! malformed one must be refused rather than half-read.

    use super::*;

    fn b(device_id: u32, key: u8, pred: Option<u8>) -> DeviceBinding {
        DeviceBinding {
            device_id,
            identity_public_key: [key; 32],
            capabilities: 1,
            replacement_predecessor: pred.map(|p| [p; 32]),
        }
    }

    fn sample() -> DeviceInventory {
        DeviceInventory {
            generation: 5,
            active: vec![b(1, 1, None), b(3, 3, Some(9))],
            revocation_floor_generation: 1,
            revoked: vec![
                Revocation {
                    binding: b(2, 2, None),
                    terminal_generation: 2,
                },
                Revocation {
                    binding: b(4, 4, Some(7)),
                    terminal_generation: 4,
                },
            ],
        }
    }

    #[test]
    fn stored_state_round_trips() {
        let inv = sample();
        assert_eq!(decode_inventory(&encode_inventory(&inv)), Some(inv));
        let empty = DeviceInventory::default();
        assert_eq!(decode_inventory(&encode_inventory(&empty)), Some(empty));
    }

    #[test]
    fn stored_state_decoder_rejects_malformed_rows() {
        let good = encode_inventory(&sample());
        assert!(
            decode_inventory(&good[..good.len() - 1]).is_none(),
            "truncated"
        );
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(decode_inventory(&trailing).is_none(), "trailing byte");
        // nine active bindings (the bound is eight), well-formed otherwise
        let nine = DeviceInventory {
            generation: 9,
            active: (1..=9).map(|i| b(i, i as u8, None)).collect(),
            ..Default::default()
        };
        assert!(
            decode_inventory(&encode_inventory(&nine)).is_none(),
            "9 active"
        );
        let nine_revoked = DeviceInventory {
            generation: 9,
            revocation_floor_generation: 0,
            revoked: (1..=9)
                .map(|i| Revocation {
                    binding: b(i, i as u8, None),
                    terminal_generation: u64::from(i),
                })
                .collect(),
            ..Default::default()
        };
        assert!(
            decode_inventory(&encode_inventory(&nine_revoked)).is_none(),
            "9 revoked"
        );
        // a presence flag other than 0 or 1
        let one = DeviceInventory {
            generation: 1,
            active: vec![b(1, 1, None)],
            ..Default::default()
        };
        let mut bad_flag = encode_inventory(&one);
        // generation(8) + count(4) + device(4) + key(32) + caps(8) = flag offset
        bad_flag[8 + 4 + 4 + 32 + 8] = 2;
        assert!(decode_inventory(&bad_flag).is_none(), "flag 2");
    }

    /// The three request encodings are compared byte for byte to detect a
    /// retry key reused for a different request, so no two operations, and no
    /// two different requests, may share an encoding.
    #[test]
    fn request_encodings_are_distinct_per_operation_and_per_field() {
        let x = b(1, 1, None);
        let y = b(2, 2, Some(5));
        let link = encode_link_request(3, &x);
        let revoke = encode_revoke_request(3, &x);
        let replace = encode_replace_request(3, &x, &y);
        assert_ne!(link, revoke);
        assert_ne!(revoke, replace);
        assert_ne!(link, replace);
        // changing any field changes the encoding
        assert_ne!(encode_link_request(4, &x), link);
        assert_ne!(encode_link_request(3, &b(1, 2, None)), link);
        assert_ne!(encode_link_request(3, &b(1, 1, Some(0))), link);
        assert_ne!(encode_revoke_request(4, &x), revoke);
        assert_ne!(encode_revoke_request(3, &y), revoke);
        assert_ne!(encode_replace_request(4, &x, &y), replace);
        assert_ne!(encode_replace_request(3, &x, &b(2, 2, None)), replace);
        assert_ne!(encode_replace_request(3, &y, &x), replace);
    }
}
