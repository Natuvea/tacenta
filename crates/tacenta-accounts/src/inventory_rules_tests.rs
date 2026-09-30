//! The inventory rules, exercised against the in-memory store (the same
//! `Accounts` behind `AccountStore::Memory`), so they need no database. The
//! rules live in `inventory.rs` as pure functions that both backends call; these
//! tests pin their refusals, the retry-key scoping, and the snapshot framing.

use crate::{Accounts, DeviceInventory, InventoryError, TenantId};
use tacenta_core::crypto::groups::inventory::{
    DeviceBinding, Error as CoreError, GROUP_EPOCH_V1, binding_commitment, issuer_public_key,
};

/// An honest device identity key: the X25519 public key of a secret that
/// repeats one byte, which is a point of the prime-order subgroup and so passes
/// the core's identity-key rule. Distinct seeds give distinct keys. (The
/// function is named for the issuer, but it only derives a public key.)
pub(crate) fn honest_key(seed: u8) -> [u8; 32] {
    issuer_public_key(&[seed; 32])
}

fn b(device_id: u32, key: u8) -> DeviceBinding {
    DeviceBinding {
        device_id,
        identity_public_key: honest_key(key),
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

// ---------------------------------------------------------------------------
// Identity keys: the core's rule, applied before anything is stored or signed.
// ---------------------------------------------------------------------------

fn key_bytes(low: &[(usize, u8)], fill: u8) -> [u8; 32] {
    let mut key = [fill; 32];
    for &(index, value) in low {
        key[index] = value;
    }
    key
}

/// The seven other spellings of `honest_key(7)` that X25519 treats as the same
/// key (`13be4f...` is the key; each of these agrees with it for every private
/// key). Computed with an independent edwards25519 implementation in Python, and
/// refused by the core as `NotPrimeOrder`.
const RESPELLINGS_OF_KEY_7: [&str; 7] = [
    "5af8922e95b31b0d50d02e6811e0c4d8c7d76866dfd916d3ce7c151d9f36ad4d",
    "7200ad34f2c7e4d05fdb5c5319a09d3bf569caf9e13a9e36e7af84f3fb9b6310",
    "ac58c257242772322113f17f553f0af06074fc37851566da4deea6266f3d1436",
    "90c34a831c10700b3525c66a2fae1ec2051e06ba688649d21f1f7e996ca6475b",
    "311f1399482dbea7e15a31d5464f91cbc90c364b704c34fdd357dc68ad97dd45",
    "72cc7429bf8e39d9086c349cdc218ea7836dedf88db2a9af0a5d34cc1b8b2235",
    "4de3b432c8941cc5cfb568b5642f5f6329980315d40d50259bbf3129ab732778",
];

fn unhex(text: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

/// Keys the specification's check 6 refuses, each with the class the core
/// gives it: the five values it lists (u = 0, 1, p - 1 and two others),
/// non-canonical spellings, a key on the twist, and other spellings of an
/// honest key.
fn refused_identity_keys() -> Vec<(String, [u8; 32], CoreError)> {
    let mut keys = vec![
        ("u = 0".to_owned(), [0; 32], CoreError::NonContributory),
        (
            "u = 1".to_owned(),
            key_bytes(&[(0, 1)], 0),
            CoreError::NonContributory,
        ),
        (
            "u = p - 1".to_owned(),
            key_bytes(&[(0, 0xec), (31, 0x7f)], 0xff),
            CoreError::NonContributory,
        ),
        (
            "listed value e0eb7a7c".to_owned(),
            unhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
            CoreError::NonContributory,
        ),
        (
            "listed value 5f9c95bc".to_owned(),
            unhex("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
            CoreError::NonContributory,
        ),
        (
            "u = 2, on the twist".to_owned(),
            key_bytes(&[(0, 2)], 0),
            CoreError::NotPrimeOrder,
        ),
        (
            "u = p, non-canonical".to_owned(),
            key_bytes(&[(0, 0xed), (31, 0x7f)], 0xff),
            CoreError::NonCanonical,
        ),
        (
            "u = p + 1, non-canonical".to_owned(),
            key_bytes(&[(0, 0xee), (31, 0x7f)], 0xff),
            CoreError::NonCanonical,
        ),
        ("all ones".to_owned(), [0xff; 32], CoreError::NonCanonical),
        (
            "u = 0 with bit 255".to_owned(),
            key_bytes(&[(31, 0x80)], 0),
            CoreError::NonCanonical,
        ),
    ];
    let mut honest_high = honest_key(7);
    honest_high[31] |= 0x80;
    keys.push((
        "an honest key with bit 255 set".to_owned(),
        honest_high,
        CoreError::NonCanonical,
    ));
    for (n, text) in RESPELLINGS_OF_KEY_7.iter().enumerate() {
        keys.push((
            format!("respelling {} of an honest key", n + 1),
            unhex(text),
            CoreError::NotPrimeOrder,
        ));
    }
    keys
}

#[test]
fn the_respelling_vectors_are_respellings_of_the_honest_key_they_name() {
    // Ties the constants above to the key the tests use, so they cannot drift.
    assert_eq!(
        honest_key(7),
        unhex("13be4feaeaf204c7fd3358fc9c00721881d174278128227ec674f37f7fe97b6d")
    );
    for text in RESPELLINGS_OF_KEY_7 {
        assert_ne!(unhex(text), honest_key(7));
    }
    // The honest key itself passes, and so does every seed the tests use.
    for seed in 1..=100u8 {
        assert_eq!(
            tacenta_core::crypto::groups::inventory::validate_identity_key(&honest_key(seed)),
            Ok(()),
            "seed {seed}"
        );
    }
}

#[test]
fn a_link_naming_a_key_the_specification_refuses_is_refused_and_stores_nothing() {
    let (mut a, t, _) = fixture();
    let snapshot_before = a.snapshot();
    for (name, key, class) in refused_identity_keys() {
        let bad = DeviceBinding {
            identity_public_key: key,
            ..b(1, 1)
        };
        assert_eq!(
            a.link_device_binding(&t, "alice", 0, [1; 32], bad),
            Err(InventoryError::IdentityKey(class)),
            "{name}"
        );
    }
    assert_eq!(
        a.device_inventory(&t, "alice"),
        Some(DeviceInventory::default())
    );
    assert_eq!(
        a.snapshot(),
        snapshot_before,
        "no inventory and no retry record was stored"
    );
    // The retry key was not used up by the refusals, and a valid key works.
    let ok = a
        .link_device_binding(&t, "alice", 0, [1; 32], b(1, 1))
        .unwrap();
    assert_eq!(ok.generation, 1);
}

#[test]
fn a_respelling_of_an_active_key_is_refused_instead_of_listed_beside_it() {
    // A respelling agrees exactly as the key it was built from, so admitting it
    // would list one private key as two devices, and removing one would leave
    // the other. The byte comparison that finds an equal key cannot see it; the
    // identity-key rule can, because it admits one spelling only.
    let (mut a, t, _) = fixture();
    let first = DeviceBinding {
        identity_public_key: honest_key(7),
        ..b(1, 7)
    };
    a.link_device_binding(&t, "alice", 0, [1; 32], first.clone())
        .unwrap();
    for text in RESPELLINGS_OF_KEY_7 {
        let respelt = DeviceBinding {
            identity_public_key: unhex(text),
            ..b(2, 7)
        };
        assert_eq!(
            a.link_device_binding(&t, "alice", 1, [2; 32], respelt),
            Err(InventoryError::IdentityKey(CoreError::NotPrimeOrder)),
            "{text}"
        );
    }
    let now = a.device_inventory(&t, "alice").unwrap();
    assert_eq!(now.generation, 1);
    assert_eq!(now.active, vec![first]);
}

#[test]
fn a_replacement_or_revocation_naming_a_refused_key_is_refused_and_changes_nothing() {
    let (mut a, t, _) = fixture();
    let first = b(1, 1);
    a.link_device_binding(&t, "alice", 0, [1; 32], first.clone())
        .unwrap();
    let before = a.device_inventory(&t, "alice").unwrap();
    let snapshot_before = a.snapshot();
    for (name, key, class) in refused_identity_keys() {
        let refused = Err(InventoryError::IdentityKey(class));
        // The replacement carries the right commitment, so the key is the only
        // fault.
        let replacement = DeviceBinding {
            identity_public_key: key,
            ..successor(&first, 2, 2)
        };
        assert_eq!(
            a.replace_device_binding(&t, "alice", 1, [2; 32], first.clone(), replacement),
            refused,
            "replace, {name}"
        );
        // A binding to retire that carries a refused key is refused as such.
        let retired = DeviceBinding {
            identity_public_key: key,
            ..first.clone()
        };
        assert_eq!(
            a.revoke_device_binding(&t, "alice", 1, [3; 32], retired.clone()),
            refused,
            "revoke, {name}"
        );
        assert_eq!(
            a.replace_device_binding(&t, "alice", 1, [4; 32], retired, successor(&first, 2, 2)),
            refused,
            "replace of a binding with a refused key, {name}"
        );
    }
    assert_eq!(a.device_inventory(&t, "alice").unwrap(), before);
    assert_eq!(a.snapshot(), snapshot_before);
    // The same retry keys work once the request is valid.
    let replaced = a
        .replace_device_binding(&t, "alice", 1, [2; 32], first, successor(&b(1, 1), 2, 2))
        .unwrap();
    assert_eq!(replaced.generation, 2);
}

// ---------------------------------------------------------------------------
// replacement_predecessor: only a replacement carries one, and only for the
// exact binding it retires.
// ---------------------------------------------------------------------------

#[test]
fn a_plain_link_carries_no_replacement_predecessor() {
    let (mut a, t, _) = fixture();
    a.link_device_binding(&t, "alice", 0, [1; 32], b(1, 1))
        .unwrap();
    a.link_device_binding(&t, "bob", 0, [1; 32], b(5, 5))
        .unwrap();
    let before = a.device_inventory(&t, "alice").unwrap();
    let snapshot_before = a.snapshot();
    let markers = [
        (
            "a device that was never linked anywhere",
            binding_commitment(&b(77, 77)).unwrap(),
        ),
        (
            "another account's active device",
            binding_commitment(&b(5, 5)).unwrap(),
        ),
        (
            "this account's own active device",
            binding_commitment(&b(1, 1)).unwrap(),
        ),
        ("all zero bytes", [0; 32]),
    ];
    for (n, (name, marker)) in markers.into_iter().enumerate() {
        let forged = DeviceBinding {
            replacement_predecessor: Some(marker),
            ..b(9, 9)
        };
        assert_eq!(
            a.link_device_binding(&t, "alice", 1, [10 + n as u8; 32], forged),
            Err(InventoryError::UnexpectedReplacementPredecessor),
            "{name}"
        );
    }
    assert_eq!(a.device_inventory(&t, "alice").unwrap(), before);
    assert_eq!(a.snapshot(), snapshot_before);
    // Without the marker the same device links.
    assert_eq!(
        a.link_device_binding(&t, "alice", 1, [10; 32], b(9, 9))
            .unwrap()
            .generation,
        2
    );
}

#[test]
fn a_replacement_must_commit_to_the_exact_binding_it_retires() {
    let (mut a, t, _) = fixture();
    a.link_device_binding(&t, "alice", 0, [1; 32], b(1, 1))
        .unwrap();
    a.link_device_binding(&t, "alice", 1, [2; 32], b(2, 2))
        .unwrap();
    a.link_device_binding(&t, "bob", 0, [1; 32], b(5, 5))
        .unwrap();
    let before = a.device_inventory(&t, "alice").unwrap();
    let snapshot_before = a.snapshot();
    let retired = b(1, 1);
    let near_miss = DeviceBinding {
        device_id: 99,
        ..retired.clone()
    };
    let markers = [
        ("none", None),
        (
            "a device that was never linked anywhere",
            Some(binding_commitment(&b(77, 77)).unwrap()),
        ),
        (
            "another account's active device",
            Some(binding_commitment(&b(5, 5)).unwrap()),
        ),
        (
            "another active device of this account",
            Some(binding_commitment(&b(2, 2)).unwrap()),
        ),
        (
            "the retired binding with one field changed",
            Some(binding_commitment(&near_miss).unwrap()),
        ),
        ("all zero bytes", Some([0; 32])),
    ];
    for (n, (name, marker)) in markers.into_iter().enumerate() {
        let wrong = DeviceBinding {
            replacement_predecessor: marker,
            ..b(3, 3)
        };
        assert_eq!(
            a.replace_device_binding(&t, "alice", 2, [20 + n as u8; 32], retired.clone(), wrong),
            Err(InventoryError::ReplacementPredecessorMismatch),
            "{name}"
        );
    }
    assert_eq!(a.device_inventory(&t, "alice").unwrap(), before);
    assert_eq!(a.snapshot(), snapshot_before);

    let right = successor(&retired, 3, 3);
    assert_eq!(
        right.replacement_predecessor,
        Some(binding_commitment(&retired).unwrap())
    );
    let replaced = a
        .replace_device_binding(&t, "alice", 2, [20; 32], retired.clone(), right.clone())
        .unwrap();
    assert_eq!(replaced.generation, 3);
    assert!(replaced.active.contains(&right));
    assert!(!replaced.active.contains(&retired));
}
