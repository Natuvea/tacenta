//! What freezes a `GroupClient` and what lifts the freeze
//! (`crates/tacenta-client/src/group_client.rs`): a direct send that committed, a recovery that
//! fails at the restore, a store that lost its snapshot, and a pending control that cannot be
//! reserved.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made. They run the live coordinator against the in-process directory and relay.
//!
//! - M007 (`group_client.rs:527`): `send_direct` never clears `poisoned` after a committed send.
//! - M008 (`group_client.rs:501`): `recover` lifts `poisoned` before the restore that can fail.
//! - M009 (`group_client.rs:500`): `recover` on a store without a snapshot is not a `Recovery`
//!   error.
//! - M020 (`group_client.rs:1036`): `dispatch_pending_controls` swallows a freeze.
//!
//! The ids (`M###`, `D##`) are those of the single-change mutation run against 97689a0; the
//! `file:line` in each test's doc comment is the change site at that commit.

use super::*;

/// M007 (`group_client.rs:527`): in `send_direct`, the `self.poisoned = false;` after
/// `commit_provider_state(..)?;` is removed, so a coordinator that has successfully committed a
/// direct send stays poisoned (frozen) for good. The existing tests only ever send one direct
/// message per coordinator (or drop it afterwards), so nothing observed the coordinator after a
/// successful send.
#[tokio::test]
async fn m007_a_direct_send_that_committed_leaves_the_coordinator_running() {
    let (directory, relay) = start_server().await;
    let store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &store).await;
    let mut bob = plain(directory, relay, "+bob").await;
    let bob_route = bob.address().clone();

    alice.send_direct(&bob_route, b"one").await.unwrap();
    assert!(
        !alice.is_frozen(),
        "a direct send that committed must clear the poison it set"
    );
    alice.send_direct(&bob_route, b"two").await.unwrap();
    assert_eq!(bob.receive().await.unwrap().len(), 2);
}

/// M008 (`group_client.rs:501`): in `recover`, `self.poisoned = false;` moves from after
/// `restore_state_in_place(..)` and `self.snapshot = snapshot;` to before the restore, so a
/// recovery that fails at the restore has already lifted the poison (and `DurableStore::recover`
/// has already lifted the store latch).
#[tokio::test]
async fn m008_a_recovery_that_fails_at_the_restore_leaves_a_poisoned_coordinator_frozen() {
    let (directory, relay) = start_server().await;
    let store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &store).await;
    let bob = plain(directory, relay, "+bob").await;
    let bob_route = bob.address().clone();

    // The ratchet advanced in memory and its commit failed: poisoned + latched.
    store.script([CommitOutcome::Failed], false);
    assert!(matches!(
        alice.send_direct(&bob_route, b"one").await,
        Err(GroupError::Frozen)
    ));
    assert!(alice.is_frozen());

    // The durable snapshot can be read but its provider state cannot be restored.
    store
        .0
        .lock()
        .unwrap()
        .snapshot
        .as_mut()
        .unwrap()
        .provider_state = vec![0xEE; 8];
    assert!(alice.recover().await.is_err());
    assert!(
        alice.is_frozen(),
        "a failed recovery must not lift the freeze"
    );
    assert!(matches!(
        alice.send_direct(&bob_route, b"two").await,
        Err(GroupError::Frozen)
    ));
}

/// M009 (`group_client.rs:500`): in `recover`, `.ok_or(GroupError::Recovery)?` after
/// `self.store.recover()` becomes `.unwrap_or_else(|| OperationSnapshot::empty(0))`, so a store
/// that holds no snapshot recovers to an empty one and the failure surfaces later as a `Client`
/// error (from restoring empty provider state) instead of `Recovery`.
#[tokio::test]
async fn m009_a_store_that_lost_its_snapshot_refuses_recovery_with_a_recovery_error() {
    let (directory, relay) = start_server().await;
    let store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &store).await;

    store.0.lock().unwrap().snapshot = None;
    assert!(matches!(alice.recover().await, Err(GroupError::Recovery)));
}

/// M020 (`group_client.rs:1036`): in `dispatch_pending_controls`, the arm
/// `Err(GroupLiveError::Frozen) => return Err(GroupError::Frozen)` becomes
/// `Err(GroupLiveError::Frozen) => {}`, so a freeze while draining committed controls is swallowed
/// and the call reports `Ok(count)`.
#[tokio::test]
async fn m020_a_freeze_while_dispatching_pending_controls_is_reported() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (bob, _) = joined(directory, relay, "+bob", &alice_member).await;
    let bob_member = bob.member().unwrap();
    let routes = vec![(bob_member.clone(), route(&bob))];
    let r1 = alice
        .next_roster(vec![alice_member.clone(), bob_member.clone()])
        .unwrap();

    // The installation and the exact control commit; the reservation is lost.
    alice_store.script([CommitOutcome::Committed, CommitOutcome::Unknown], false);
    assert!(matches!(
        alice.install_roster(r1, &routes, None, 0).await,
        Err(GroupError::Frozen)
    ));
    alice.recover().await.unwrap();

    // Now the reservation of the pending control does not commit.
    alice_store.script([CommitOutcome::Failed], false);
    assert!(matches!(
        alice.dispatch_pending_controls(&routes).await,
        Err(GroupError::Frozen)
    ));
    assert!(alice.is_frozen());
}
