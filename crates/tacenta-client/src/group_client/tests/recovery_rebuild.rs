//! A `GroupClient::recover` that restores the provider state and then cannot rebuild the group state
//! (decision 0143, `crates/tacenta-client/src/group_client.rs`): it must report the failure, keep the
//! coordinator frozen and keep the group state it had, and it can be repeated.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made. They run the live coordinator against the in-process directory and relay.
//!
//! - M008r3: `recover` clears the poison before it rebuilds the group state.
//! - M008r4: `recover` ignores a failed rebuild of the group state.
//!
//! `M008r3` and `M008r4` re-express M008 of the run against 97689a0, whose text no longer patches
//! because `recover` now sets the poison first and clears it last (ids of the run against 341e2b0).

use super::*;

/// Alice (authority) with Bob in the group at revision 1, and Alice's stored snapshot changed so that
/// her group state cannot be rebuilt from it (the receiver record is garbage) while her provider
/// state is intact. Returns Alice, her store and the receiver record the store held.
async fn alice_whose_group_cannot_be_rebuilt() -> (GroupClient, SharedStore, Vec<u8>) {
    let (directory, relay) = start_server().await;
    let store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (bob, _bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let bob_member = bob.member().unwrap();
    let r1 = alice
        .next_roster(vec![alice_member, bob_member.clone()])
        .unwrap();
    alice
        .install_roster(r1, &[(bob_member, route(&bob))], None, 0)
        .await
        .unwrap();
    let good = store.durable().unwrap().application_state;
    assert!(!good.is_empty());
    store
        .0
        .lock()
        .unwrap()
        .snapshot
        .as_mut()
        .unwrap()
        .application_state = vec![0xEE; 16];
    (alice, store, good)
}

/// M008r3: in `recover`, `self.poisoned = false;` moves from the end to before the group state is
/// rebuilt, so a recovery whose rebuild fails has lifted the poison (and `DurableStore::recover` has
/// lifted the store latch) and the coordinator runs again.
#[tokio::test]
async fn m008r3_a_recovery_that_cannot_rebuild_the_group_state_leaves_the_coordinator_frozen() {
    let (mut alice, store, good) = alice_whose_group_cannot_be_rebuilt().await;
    let roster = alice.roster().unwrap().clone();
    let failed = alice.recover().await;
    assert!(matches!(failed, Err(GroupError::Recovery)), "{failed:?}");
    assert!(
        alice.is_frozen(),
        "a failed recovery must not lift the freeze"
    );
    assert_eq!(
        alice.roster().unwrap(),
        &roster,
        "a rebuild that failed keeps the group state it had"
    );
    assert!(matches!(
        alice.dispatch_pending_controls(&[]).await,
        Err(GroupError::Frozen)
    ));
    // The call can be repeated once the store can be read again.
    store
        .0
        .lock()
        .unwrap()
        .snapshot
        .as_mut()
        .unwrap()
        .application_state = good;
    alice.recover().await.unwrap();
    assert!(!alice.is_frozen());
}

/// M008r4: in `recover`, `self.attach(group_id, authority, source)?;` becomes
/// `let _ = self.attach(..);`, so a recovery whose rebuild of the group state failed reports success.
#[tokio::test]
async fn m008r4_a_recovery_reports_the_failure_to_rebuild_the_group_state() {
    let (mut alice, _store, _good) = alice_whose_group_cannot_be_rebuilt().await;
    let failed = alice.recover().await;
    assert!(matches!(failed, Err(GroupError::Recovery)), "{failed:?}");
}
