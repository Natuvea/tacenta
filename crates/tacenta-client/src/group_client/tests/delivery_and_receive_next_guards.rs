//! `GroupClient::acknowledge_delivery` and the conditions on which `GroupClient::receive_next`
//! returns instead of waiting for mail (decision 0144,
//! `crates/tacenta-client/src/group_client.rs`).
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made. They run the live coordinator against the in-process directory and relay. Every wait is
//! bounded, so that a `receive_next` that would wait for mail that never comes fails the test
//! instead of hanging it.
//!
//! - R051: `acknowledge_delivery` commits the cursor of a coordinator that is frozen only by its poison.
//! - R064, R065, R066, R067, R068: `receive_next` does not stop waiting for redelivered events, lost
//!   events, a direct message, a dropped item or a frozen batch.
//!
//! The ids (`R###`) are those of the single-change mutation run against 341e2b0.

use super::*;
use std::time::Duration;

/// How long a `receive_next` that has something to return may take.
const BOUND: Duration = Duration::from_secs(10);

/// Alice (authority) and Bob at revision 1, both coordinators with stores.
struct Duo {
    alice: GroupClient,
    bob: GroupClient,
    bob_store: SharedStore,
    bob_config: Config,
    alice_member: Member,
    bob_member: Member,
    alice_route: DeviceAddr,
    bob_route: DeviceAddr,
}

async fn duo() -> Duo {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let (bob_member, bob_route) = (bob.member().unwrap(), route(&bob));
    let r1 = alice
        .next_roster(vec![alice_member.clone(), bob_member.clone()])
        .unwrap();
    alice
        .install_roster(r1, &[(bob_member.clone(), bob_route.clone())], None, 0)
        .await
        .unwrap();
    bob.receive(0).await.unwrap();
    Duo {
        alice_route: route(&alice),
        alice,
        bob,
        bob_store,
        bob_config: config(directory, relay, "+bob", 1),
        alice_member,
        bob_member,
        bob_route,
    }
}

impl Duo {
    async fn send(&mut self, text: &str) {
        self.alice
            .send_group(
                &[(self.bob_member.clone(), self.bob_route.clone())],
                text.as_bytes().to_vec(),
            )
            .await
            .unwrap();
    }
}

/// R051: in `acknowledge_delivery`, the `is_frozen` check that comes first is removed, so a
/// coordinator that is frozen only by its poison (a failed recovery lifted the store's latch but not
/// the poison) still commits the delivery cursor.
#[tokio::test]
async fn r051_a_poisoned_coordinator_does_not_commit_the_delivery_cursor() {
    let mut d = duo().await;
    d.send("one").await;
    assert_eq!(d.bob.receive(0).await.unwrap().events().len(), 1);
    // A direct send whose commit fails poisons Bob and latches his store.
    d.bob_store.script([CommitOutcome::Failed], false);
    let sent = d.bob.send_direct(&d.alice_route, b"x").await;
    assert!(matches!(sent, Err(GroupError::Frozen)), "{sent:?}");
    // A recovery that cannot restore the provider state reads the store, which lifts the latch,
    // and fails, which must leave the poison.
    d.bob_store
        .0
        .lock()
        .unwrap()
        .snapshot
        .as_mut()
        .unwrap()
        .provider_state = vec![0xEE; 8];
    assert!(d.bob.recover().await.is_err());
    assert!(d.bob.is_frozen());
    let cursor = d.bob_store.durable().unwrap().delivery_cursor;
    let refused = d.bob.acknowledge_delivery();
    assert!(matches!(refused, Err(GroupError::Frozen)), "{refused:?}");
    assert_eq!(d.bob_store.durable().unwrap().delivery_cursor, cursor);
}

/// Bob's coordinator started again from what his store holds, as after a crash.
async fn bob_again(config: &Config, store: &SharedStore, alice_member: &Member) -> GroupClient {
    let mut bob = restart(config, store).await;
    bob.join_group(genesis_of(alice_member), alice_member.clone())
        .unwrap();
    bob
}

/// R064: in `receive_next`, `&& inbound.redelivered.is_empty()` is removed from the test for an
/// empty batch, so events waiting to be offered again do not end the wait.
#[tokio::test]
async fn r064_receive_next_returns_at_once_when_events_are_waiting_to_be_offered_again() {
    let mut d = duo().await;
    d.send("one").await;
    assert_eq!(d.bob.receive(0).await.unwrap().events().len(), 1);
    drop(d.bob);
    let mut bob = bob_again(&d.bob_config, &d.bob_store, &d.alice_member).await;
    let inbound = tokio::time::timeout(BOUND, bob.receive_next(0))
        .await
        .expect("events waiting to be offered again end the wait")
        .unwrap();
    assert_eq!(inbound.redelivered.len(), 1);
    assert!(inbound.items.is_empty() && inbound.direct.is_empty());
}

/// R065: in `receive_next`, `&& inbound.lost_events == 0` is removed from the test for an empty
/// batch, so events that were issued and can no longer be offered do not end the wait.
#[tokio::test]
async fn r065_receive_next_returns_at_once_when_events_were_lost() {
    let mut d = duo().await;
    d.send("a").await;
    d.send("b").await;
    assert_eq!(d.bob.receive(0).await.unwrap().events().len(), 2);
    // The retention has dropped the records of both before they were acknowledged.
    d.bob_store
        .0
        .lock()
        .unwrap()
        .snapshot
        .as_mut()
        .unwrap()
        .inbox
        .clear();
    drop(d.bob);
    let mut bob = bob_again(&d.bob_config, &d.bob_store, &d.alice_member).await;
    let inbound = tokio::time::timeout(BOUND, bob.receive_next(0))
        .await
        .expect("lost events end the wait")
        .unwrap();
    assert_eq!(inbound.lost_events, 2);
    assert!(inbound.redelivered.is_empty() && inbound.items.is_empty());
}

/// R066: in `receive_next`, `&& inbound.direct.is_empty()` is removed from the test for an empty
/// batch, so a direct message that arrives while it waits does not end the wait.
#[tokio::test]
async fn r066_receive_next_returns_a_direct_message_that_arrives_while_it_waits() {
    let (directory, relay) = start_server().await;
    let mut alice = plain(directory, relay, "+alice").await;
    let store = SharedStore::default();
    let mut bob = coordinator(directory, relay, "+bob", &store).await;
    let bob_route = bob.address().clone();
    let (sent, received) = tokio::join!(
        async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            alice.send_as(&bob_route, b"late", Kind::Dm).await
        },
        tokio::time::timeout(BOUND, bob.receive_next(0))
    );
    sent.unwrap();
    let inbound = received.expect("a direct message ends the wait").unwrap();
    assert_eq!(inbound.direct.len(), 1);
    assert_eq!(inbound.direct[0].plaintext, b"late");
}

/// R067: in `receive_next`, `&& inbound.dropped == 0` is removed from the test for an empty batch, so
/// an item the provider refused does not end the wait.
#[tokio::test]
async fn r067_receive_next_returns_when_the_only_item_was_dropped() {
    let (directory, relay) = start_server().await;
    let mut alice = plain(directory, relay, "+alice").await;
    let store = SharedStore::default();
    let mut bob = coordinator(directory, relay, "+bob", &store).await;
    let bob_route = bob.address().clone();
    alice
        .dispatch_group_ciphertext(&bob_route, b"not a ciphertext")
        .await
        .unwrap();
    let inbound = tokio::time::timeout(BOUND, bob.receive_next(0))
        .await
        .expect("a dropped item ends the wait")
        .unwrap();
    assert_eq!(inbound.dropped, 1);
    assert!(inbound.items.is_empty() && inbound.direct.is_empty());
}

/// R068: in `receive_next`, `&& !inbound.frozen` is removed from the test for an empty batch, so a
/// batch that stopped at a freeze is not returned: the loop calls `receive` again, which reports
/// `Frozen` as an error and loses the batch.
#[tokio::test]
async fn r068_receive_next_returns_a_batch_that_stopped_at_a_freeze() {
    let mut d = duo().await;
    d.send("one").await;
    d.bob_store.script([CommitOutcome::Failed], false);
    let inbound = tokio::time::timeout(BOUND, d.bob.receive_next(0))
        .await
        .expect("a batch that froze ends the wait")
        .expect("the batch is returned, not an error");
    assert!(inbound.frozen);
    assert!(d.bob.is_frozen());
}
