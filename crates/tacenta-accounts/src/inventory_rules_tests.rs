//! The inventory rules, exercised against the in-memory store (the same
//! `Accounts` behind `AccountStore::Memory`), so they need no database. The
//! rules live in `inventory.rs` as pure functions that both backends call; these
//! tests pin their refusals, the retry-key scoping, and the snapshot framing.

use crate::{Accounts, DeviceInventory, InventoryError, TenantId};
use tacenta_core::crypto::groups::inventory::{DeviceBinding, GROUP_EPOCH_V1, binding_commitment};

fn b(device_id: u32, key: u8) -> DeviceBinding {
    DeviceBinding {
        device_id,
        identity_public_key: [key; 32],
        capabilities: GROUP_EPOCH_V1,
        replacement_predecessor: None,
    }
}

fn successor(of: &DeviceBinding, device_id: u32, key: u8) -> DeviceBinding {
    DeviceBinding {
        replacement_predecessor: Some(binding_commitment(of).unwrap()),
        ..b(device_id, key)
    }
}

/// tenant "acme" with alice and bob; tenant "beta" with carol only.
fn fixture() -> (Accounts, TenantId, TenantId) {
    let mut a = Accounts::new();
    let (t1, _) = a
        .sign_up_tenant("acme", "admin@acme.example", "correct horse")
        .unwrap();
    a.sign_up_user(&t1.id, "alice", "hunter2!!").unwrap();
    a.sign_up_user(&t1.id, "bob", "hunter2!!").unwrap();
    let (t2, _) = a
        .sign_up_tenant("beta", "admin@beta.example", "correct horse")
        .unwrap();
    a.sign_up_user(&t2.id, "carol", "hunter2!!").unwrap();
    (a, t1.id, t2.id)
}

#[test]
fn replay_same_key_same_body_returns_the_original_result_and_does_not_reapply() {
    let (mut a, t, _) = fixture();
    let first = a
        .link_device_binding(&t, "alice", 0, [1; 32], b(1, 1))
        .unwrap();
    assert_eq!(first.generation, 1);
    // Advance past the first result.
    a.link_device_binding(&t, "alice", 1, [2; 32], b(2, 2))
        .unwrap();
    let revoked = a
        .revoke_device_binding(&t, "alice", 2, [3; 32], b(2, 2))
        .unwrap();
    assert_eq!(revoked.generation, 3);
    a.link_device_binding(&t, "alice", 3, [4; 32], b(3, 3))
        .unwrap();
    let now = a.device_inventory(&t, "alice").unwrap();
    assert_eq!(now.generation, 4);

    // Link replay returns generation 1, not the current inventory.
    assert_eq!(
        a.link_device_binding(&t, "alice", 0, [1; 32], b(1, 1))
            .unwrap(),
        first
    );
    // Lifecycle replay returns the generation-3 result.
    assert_eq!(
        a.revoke_device_binding(&t, "alice", 2, [3; 32], b(2, 2))
            .unwrap(),
        revoked
    );
    // Neither replay re-applied anything.
    assert_eq!(a.device_inventory(&t, "alice").unwrap(), now);
}

#[test]
fn same_key_with_a_changed_request_is_refused_and_changes_nothing() {
    let (mut a, t, _) = fixture();
    a.link_device_binding(&t, "alice", 0, [1; 32], b(1, 1))
        .unwrap();
    let before = a.device_inventory(&t, "alice").unwrap();

    // (i) different binding, same predecessor
    assert_eq!(
        a.link_device_binding(&t, "alice", 0, [1; 32], b(2, 2)),
        Err(InventoryError::IdempotencyConflict)
    );
    // (ii) same binding, different predecessor (DuplicateBinding would
    // otherwise be the answer: the conflict must win)
    assert_eq!(
        a.link_device_binding(&t, "alice", 1, [1; 32], b(1, 1)),
        Err(InventoryError::IdempotencyConflict)
    );
    // (iii) link key reused for a revoke
    assert_eq!(
        a.revoke_device_binding(&t, "alice", 1, [1; 32], b(1, 1)),
        Err(InventoryError::IdempotencyConflict)
    );
    // (iv) lifecycle key reused for a link, and for a changed replacement
    let s = successor(&b(1, 1), 2, 2);
    a.replace_device_binding(&t, "alice", 1, [9; 32], b(1, 1), s.clone())
        .unwrap();
    let after_replace = a.device_inventory(&t, "alice").unwrap();
    assert_eq!(
        a.link_device_binding(&t, "alice", 2, [9; 32], b(5, 5)),
        Err(InventoryError::IdempotencyConflict)
    );
    let s2 = successor(&b(1, 1), 3, 3);
    assert_eq!(
        a.replace_device_binding(&t, "alice", 1, [9; 32], b(1, 1), s2),
        Err(InventoryError::IdempotencyConflict)
    );
    assert_eq!(
        a.revoke_device_binding(&t, "alice", 1, [9; 32], b(1, 1)),
        Err(InventoryError::IdempotencyConflict)
    );
    assert_ne!(before, after_replace);
    assert_eq!(a.device_inventory(&t, "alice").unwrap(), after_replace);
}

#[test]
fn another_account_cannot_replay_or_read_this_accounts_records() {
    let (mut a, t1, t2) = fixture();
    let alice = a
        .link_device_binding(&t1, "alice", 0, [1; 32], b(1, 1))
        .unwrap();
    let s = successor(&b(1, 1), 2, 2);
    let alice2 = a
        .replace_device_binding(&t1, "alice", 1, [2; 32], b(1, 1), s.clone())
        .unwrap();

    // Same key and a different binding on bob: a fresh mutation on bob, not a
    // replay of (or conflict with) alice's record.
    let bob = a
        .link_device_binding(&t1, "bob", 0, [1; 32], b(7, 7))
        .unwrap();
    assert_eq!(bob.active, vec![b(7, 7)]);
    assert_ne!(bob, alice);
    // Alice's own retry still returns alice's record.
    assert_eq!(
        a.link_device_binding(&t1, "alice", 0, [1; 32], b(1, 1))
            .unwrap(),
        alice
    );
    // Bob presenting alice's replace key and body does not receive alice's
    // result: alice's retired binding is not active on bob.
    assert_eq!(
        a.replace_device_binding(&t1, "bob", 1, [2; 32], b(1, 1), s.clone()),
        Err(InventoryError::BindingNotActive)
    );
    assert_eq!(
        a.revoke_device_binding(&t1, "bob", 1, [8; 32], b(1, 1)),
        Err(InventoryError::BindingNotActive)
    );
    // Unknown user / a user of another tenant.
    assert_eq!(
        a.link_device_binding(&t1, "mallory", 0, [1; 32], b(1, 1)),
        Err(InventoryError::UnknownUser)
    );
    assert_eq!(
        a.link_device_binding(&t2, "alice", 0, [1; 32], b(1, 1)),
        Err(InventoryError::UnknownUser)
    );
    assert_eq!(a.device_inventory(&t2, "alice"), None);
    // Same username string in another tenant is independent (carol here).
    let carol = a
        .link_device_binding(&t2, "carol", 0, [1; 32], b(1, 1))
        .unwrap();
    assert_eq!(carol.generation, 1);
    assert_eq!(a.device_inventory(&t1, "alice").unwrap(), alice2);
    assert_eq!(a.device_inventory(&t1, "bob").unwrap(), bob);
}

#[test]
fn superseded_or_stale_requests_are_refused_and_do_not_burn_the_key() {
    let (mut a, t, _) = fixture();
    a.link_device_binding(&t, "alice", 0, [1; 32], b(1, 1))
        .unwrap();
    let s = successor(&b(1, 1), 2, 2);
    a.replace_device_binding(&t, "alice", 1, [2; 32], b(1, 1), s.clone())
        .unwrap(); // generation 2, device 1 retired
    let now = a.device_inventory(&t, "alice").unwrap();
    assert_eq!(now.generation, 2);

    // Stale and future predecessors, all three operations, fresh keys.
    for pred in [0u64, 1, 3, 99] {
        assert_eq!(
            a.link_device_binding(&t, "alice", pred, [10; 32], b(3, 3)),
            Err(InventoryError::PredecessorMismatch),
            "link at {pred}"
        );
        assert_eq!(
            a.revoke_device_binding(&t, "alice", pred, [11; 32], s.clone()),
            Err(InventoryError::PredecessorMismatch),
            "revoke at {pred}"
        );
        let s3 = successor(&s, 3, 3);
        assert_eq!(
            a.replace_device_binding(&t, "alice", pred, [12; 32], s.clone(), s3),
            Err(InventoryError::PredecessorMismatch),
            "replace at {pred}"
        );
    }
    // The already-retired binding is not active any more.
    assert_eq!(
        a.revoke_device_binding(&t, "alice", 2, [13; 32], b(1, 1)),
        Err(InventoryError::BindingNotActive)
    );
    let s4 = successor(&b(1, 1), 4, 4);
    assert_eq!(
        a.replace_device_binding(&t, "alice", 2, [14; 32], b(1, 1), s4),
        Err(InventoryError::BindingNotActive)
    );
    // A retired binding, its device id, and its key cannot come back.
    assert_eq!(
        a.link_device_binding(&t, "alice", 2, [15; 32], b(1, 1)),
        Err(InventoryError::BindingRevoked)
    );
    assert_eq!(
        a.link_device_binding(&t, "alice", 2, [16; 32], b(1, 9)),
        Err(InventoryError::DeviceIdRetired)
    );
    assert_eq!(
        a.link_device_binding(&t, "alice", 2, [17; 32], b(9, 1)),
        Err(InventoryError::IdentityKeyInUse)
    );
    // None of that changed state.
    assert_eq!(a.device_inventory(&t, "alice").unwrap(), now);
    // A refusal is not recorded: the same key succeeds once the request is
    // correct.
    let ok = a
        .link_device_binding(&t, "alice", 2, [10; 32], b(3, 3))
        .unwrap();
    assert_eq!(ok.generation, 3);
}

#[test]
fn evicted_revocations_can_be_relinked_after_eight_more_revocations() {
    // Documents the intended bound, stated on `InventoryError::BindingRevoked`
    // and `DeviceIdRetired`: only the eight most recent revocations are kept, and
    // `revocation_floor_generation` records what was dropped.
    let (mut a, t, _) = fixture();
    let first = b(1, 1);
    a.link_device_binding(&t, "alice", 0, [1; 32], first.clone())
        .unwrap();
    let mut current = first.clone();
    for id in 2..=10u32 {
        let next = successor(&current, id, id as u8);
        a.replace_device_binding(
            &t,
            "alice",
            u64::from(id - 1),
            [id as u8; 32],
            current,
            next.clone(),
        )
        .unwrap();
        current = next;
    }
    let inv = a.device_inventory(&t, "alice").unwrap();
    assert_eq!(inv.generation, 10);
    assert_eq!(inv.revocation_floor_generation, 2);
    assert!(!inv.revoked.iter().any(|r| r.binding == first));
    // The exact binding retired at generation 2 is accepted as new.
    let relinked = a.link_device_binding(&t, "alice", 10, [99; 32], first.clone());
    assert!(
        relinked.is_ok(),
        "evicted revoked binding is relinkable: {relinked:?}"
    );
}

#[test]
fn snapshot_restore_accepts_every_older_framing() {
    let mut empty = Accounts::new();
    let (t2, _) = empty
        .sign_up_tenant("zed", "admin@zed.example", "correct horse")
        .unwrap();
    empty.sign_up_user(&t2.id, "zoe", "hunter2!!").unwrap();
    let full = empty.snapshot();
    // three trailing u32 counts: inventories, link mutations, lifecycle mutations
    for cut in [4usize, 8, 12] {
        let bytes = &full[..full.len() - cut];
        let restored = Accounts::restore(bytes);
        assert!(restored.is_some(), "framing with {cut} trailing bytes cut");
        assert_eq!(
            restored.unwrap().device_inventory(&t2.id, "zoe"),
            Some(DeviceInventory::default())
        );
    }
    // Something in between the framings is refused.
    assert!(Accounts::restore(&full[..full.len() - 2]).is_none());
}

#[tokio::test]
async fn memory_store_maps_inventory_refusals_to_typed_store_errors() {
    use crate::{AccountStore, StoreError};
    let (a, t, _) = fixture();
    let store = AccountStore::memory(a);
    store
        .link_device_binding(&t, "alice", 0, [1; 32], b(1, 1))
        .await
        .unwrap();
    assert!(matches!(
        store
            .link_device_binding(&t, "alice", 0, [1; 32], b(2, 2))
            .await,
        Err(StoreError::Inventory(InventoryError::IdempotencyConflict))
    ));
    assert!(matches!(
        store
            .link_device_binding(&t, "nobody", 0, [1; 32], b(2, 2))
            .await,
        Err(StoreError::Inventory(InventoryError::UnknownUser))
    ));
    assert_eq!(store.device_inventory(&t, "nobody").await.unwrap(), None);
}

#[test]
fn lifecycle_operations_refuse_unknown_users_duplicates_and_invalid_bindings() {
    let (mut a, t, t2) = fixture();
    assert_eq!(
        a.revoke_device_binding(&t, "mallory", 0, [1; 32], b(1, 1)),
        Err(InventoryError::UnknownUser)
    );
    assert_eq!(
        a.replace_device_binding(
            &t,
            "mallory",
            0,
            [1; 32],
            b(1, 1),
            successor(&b(1, 1), 2, 2)
        ),
        Err(InventoryError::UnknownUser)
    );
    assert_eq!(
        a.revoke_device_binding(&t2, "alice", 0, [1; 32], b(1, 1)),
        Err(InventoryError::UnknownUser)
    );
    a.link_device_binding(&t, "alice", 0, [1; 32], b(1, 1))
        .unwrap();
    a.link_device_binding(&t, "alice", 1, [2; 32], b(2, 2))
        .unwrap();
    // an active identity key under a new device id
    assert_eq!(
        a.link_device_binding(&t, "alice", 2, [3; 32], b(3, 1)),
        Err(InventoryError::IdentityKeyInUse)
    );
    // an active device id under a new key
    assert_eq!(
        a.link_device_binding(&t, "alice", 2, [4; 32], b(1, 9)),
        Err(InventoryError::DeviceIdInUse)
    );
    // a replacement that takes over a different active device's key
    assert_eq!(
        a.replace_device_binding(&t, "alice", 2, [5; 32], b(1, 1), successor(&b(1, 1), 3, 2)),
        Err(InventoryError::IdentityKeyInUse)
    );
    // a replacement that does not commit to the binding it retires
    assert_eq!(
        a.replace_device_binding(&t, "alice", 2, [6; 32], b(1, 1), b(3, 3)),
        Err(InventoryError::ReplacementPredecessorMismatch)
    );
    // capability bits outside the v1 set, or none at all
    for caps in [0u64, 2, 3] {
        assert_eq!(
            a.link_device_binding(
                &t,
                "alice",
                2,
                [7; 32],
                DeviceBinding {
                    capabilities: caps,
                    ..b(3, 3)
                }
            ),
            Err(InventoryError::Invalid),
            "capabilities {caps}"
        );
    }
    assert_eq!(a.device_inventory(&t, "alice").unwrap().generation, 2);
}

#[test]
fn the_ninth_active_binding_and_an_exhausted_generation_are_refused() {
    use crate::inventory::{link_inventory, revoke_inventory};
    let (mut a, t, _) = fixture();
    for i in 1..=8u32 {
        a.link_device_binding(&t, "alice", u64::from(i - 1), [i as u8; 32], b(i, i as u8))
            .unwrap();
    }
    assert_eq!(
        a.link_device_binding(&t, "alice", 8, [9; 32], b(9, 9)),
        Err(InventoryError::Invalid)
    );
    assert_eq!(a.device_inventory(&t, "alice").unwrap().generation, 8);

    let maxed = DeviceInventory {
        generation: u64::MAX,
        active: vec![b(1, 1)],
        ..Default::default()
    };
    assert_eq!(
        link_inventory("acme/alice", &maxed, u64::MAX, b(2, 2)),
        Err(InventoryError::GenerationExhausted)
    );
    assert_eq!(
        revoke_inventory("acme/alice", &maxed, u64::MAX, b(1, 1)),
        Err(InventoryError::GenerationExhausted)
    );
}
