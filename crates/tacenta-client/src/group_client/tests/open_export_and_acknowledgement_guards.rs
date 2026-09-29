//! Guards at the level of `GroupClient` for the state check of `open` (decision 0143), the order of
//! the exported peers, and the acknowledgement of delivered events (decision 0144). They came from
//! a mutation run of the second fix round. Every test drives `GroupClient` against the in-process
//! directory and relay with the real provider.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc
//! comment is made.
//!
//! - `open` compares only the length of the exported state with the snapshot's.
//! - `open` takes a store that cannot be read for an empty one.
//! - The peers are exported in descending address order, or in the order of their user alone.
//! - `acknowledge_delivery` commits twice.
//! - `receive` ignores a failed acknowledgement commit and goes on to process mail.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

/// (alice, bob, bob_store): alice is the authority of a group whose roster admits bob, and bob has
/// installed it.
async fn alice_and_group_bob() -> (GroupClient, GroupClient, SharedStore, Member, DeviceAddr) {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let (bob_member, bob_route) = (bob.member().unwrap(), route(&bob));
    let r1 = alice
        .next_roster(vec![alice_member, bob_member.clone()])
        .unwrap();
    alice
        .install_roster(r1, &[(bob_member.clone(), bob_route.clone())], None, 0)
        .await
        .unwrap();
    bob.receive(0).await.unwrap();
    (alice, bob, bob_store, bob_member, bob_route)
}

/// In `open`, `client.export_state().await? != snapshot.provider_state` becomes a comparison
/// of the two lengths, so a client whose state has the snapshot's length and differs from it in a
/// byte is accepted. The snapshot here differs from the client's state in the last byte (the
/// state's generation), which changes no length.
#[tokio::test]
async fn open_refuses_a_state_that_differs_from_the_snapshots_in_one_byte() {
    let (directory, relay) = start_server().await;
    let client_config = config(directory, relay, "+alice", 1);
    let store = SharedStore::default();
    let alice = GroupClient::open(
        DefaultClient::connect(&client_config).await.unwrap(),
        store.clone(),
    )
    .await
    .unwrap();
    let state = alice.client.export_state().await.unwrap();
    drop(alice);
    let mut altered = store.durable().unwrap();
    assert_eq!(altered.provider_state, state);
    let last = altered.provider_state.len() - 1;
    altered.provider_state[last] ^= 1;
    store.0.lock().unwrap().snapshot = Some(altered.clone());
    let client = DefaultClient::connect_with_state(&client_config, &state)
        .await
        .unwrap();
    let refused = GroupClient::open(client, store.clone()).await;
    assert!(
        matches!(refused, Err(GroupError::StateMismatch)),
        "{:?}",
        refused.err()
    );
    assert_eq!(
        store.durable().unwrap(),
        altered,
        "a refused open writes nothing"
    );
}

/// A store whose reads always fail and that counts the writes it is offered.
struct Unreadable(Arc<AtomicUsize>);

impl OperationStore for Unreadable {
    fn commit(&mut self, _snapshot: &OperationSnapshot) -> CommitOutcome {
        self.0.fetch_add(1, Ordering::SeqCst);
        CommitOutcome::Committed
    }
    fn recover(&mut self) -> Result<Option<OperationSnapshot>, StoreError> {
        Err(StoreError)
    }
}

/// In `open`, `store.recover().map_err(|_| GroupError::Recovery)?` becomes
/// `store.recover().unwrap_or(None)`, so a store that cannot be read is taken for an empty one and
/// `open` goes on to publish a first snapshot to it (the fence then refuses that write, and the
/// caller gets `Frozen` instead of the `Recovery` it must get).
#[tokio::test]
async fn open_refuses_a_store_that_cannot_be_read_as_recovery_and_writes_nothing() {
    let (directory, relay) = start_server().await;
    let writes = Arc::new(AtomicUsize::new(0));
    let refused = GroupClient::open(
        plain(directory, relay, "+alice").await,
        Unreadable(writes.clone()),
    )
    .await;
    assert!(
        matches!(refused, Err(GroupError::Recovery)),
        "{:?}",
        refused.err()
    );
    assert_eq!(writes.load(Ordering::SeqCst), 0);
}

/// In `export_body_v3` the peers are sorted by user only, so several devices of one user
/// keep the order of the set they came from, which differs between the original client and one
/// restored from its export. Three devices of one peer are in the client's sessions here.
#[tokio::test]
async fn the_export_is_a_function_of_the_state_with_three_devices_of_one_peer() {
    let (directory, relay) = start_server().await;
    let client_config = config(directory, relay, "+alice", 1);
    let store = SharedStore::default();
    let mut alice = GroupClient::open(
        DefaultClient::connect(&client_config).await.unwrap(),
        store.clone(),
    )
    .await
    .unwrap();
    for device in [1u8, 2, 3] {
        let peer = DefaultClient::connect(&config(directory, relay, "+bob", device))
            .await
            .unwrap();
        alice.send_direct(peer.address(), b"hello").await.unwrap();
    }
    drop(alice);
    for round in 0..12 {
        let state = recovered_provider_state(&mut store.clone())
            .unwrap()
            .expect("the store holds a snapshot");
        let client = DefaultClient::connect_with_state(&client_config, &state)
            .await
            .unwrap();
        let opened = GroupClient::open(client, store.clone()).await;
        assert!(opened.is_ok(), "round {round}: {:?}", opened.err());
    }
}

/// The `(user, device)` of each session in the sessions section of an exported state, in the order
/// they are written (the open provider's layout: a count, then per session a length-prefixed user,
/// one device byte and a length-prefixed session).
fn exported_session_addresses(state: &[u8]) -> Vec<(String, u8)> {
    fn take(bytes: &[u8], count: usize) -> (&[u8], &[u8]) {
        bytes.split_at(count)
    }
    fn take_u32(bytes: &[u8]) -> (usize, &[u8]) {
        let (head, rest) = take(bytes, 4);
        (u32::from_be_bytes(head.try_into().unwrap()) as usize, rest)
    }
    let split = crate::split_state(state).unwrap();
    let (count, mut rest) = take_u32(split.sessions);
    let mut addresses = Vec::new();
    for _ in 0..count {
        let (length, after) = take_u32(rest);
        let (user, after) = take(after, length);
        let (device, after) = after.split_first().unwrap();
        let (length, after) = take_u32(after);
        let (_session, after) = take(after, length);
        rest = after;
        addresses.push((String::from_utf8(user.to_vec()).unwrap(), *device));
    }
    addresses
}

/// The sessions of an exported state are listed in the order of the peers'
/// addresses (0143), whatever order they were established in. The mutants sort in descending
/// order, by device alone or by user alone.
#[tokio::test]
async fn the_export_lists_the_peers_in_address_order() {
    let (directory, relay) = start_server().await;
    let store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &store).await;
    // Established in an order that is neither ascending nor descending.
    for (user, device) in [("+carol", 1u8), ("+bob", 2), ("+dave", 1), ("+bob", 1)] {
        let peer = DefaultClient::connect(&config(directory, relay, user, device))
            .await
            .unwrap();
        alice.send_direct(peer.address(), b"hello").await.unwrap();
    }
    let state = alice.client.export_state().await.unwrap();
    let expected: Vec<(String, u8)> = [("+bob", 1u8), ("+bob", 2), ("+carol", 1), ("+dave", 1)]
        .into_iter()
        .map(|(user, device)| (user.to_string(), device))
        .collect();
    assert_eq!(exported_session_addresses(&state), expected);
}

/// `acknowledge_delivery` commits the cursor twice. The acknowledgement is one commit that
/// advances the cursor and scrubs the delivered records (0144): one generation, one write.
#[tokio::test]
async fn an_acknowledgement_is_exactly_one_commit() {
    let (mut alice, mut bob, bob_store, bob_member, bob_route) = alice_and_group_bob().await;
    alice
        .send_group(&[(bob_member, bob_route)], b"one commit".to_vec())
        .await
        .unwrap();
    assert_eq!(bob.receive(0).await.unwrap().events().len(), 1);
    let generation = bob.generation();
    let writes = bob_store.attempted_generations().len();
    bob.acknowledge_delivery().unwrap();
    assert_eq!(bob.delivery_cursor(), 1);
    assert_eq!(bob.generation(), generation + 1);
    assert_eq!(bob_store.attempted_generations().len(), writes + 1);
    assert_eq!(bob_store.durable().unwrap().generation, generation + 1);
}

/// In `receive`, `self.acknowledge_delivery()?` becomes `let _ = ...`, so when the
/// acknowledgement commit of the previous call fails, the call goes on: it decrypts the mail that
/// is waiting under a coordinator that has just frozen and reports an `Inbound` instead of the
/// error.
#[tokio::test]
async fn a_failed_acknowledgement_at_the_start_of_receive_is_the_error_of_the_call() {
    let (mut alice, mut bob, bob_store, bob_member, bob_route) = alice_and_group_bob().await;
    let to_bob = [(bob_member, bob_route)];
    alice.send_group(&to_bob, b"first".to_vec()).await.unwrap();
    assert_eq!(bob.receive(0).await.unwrap().events().len(), 1);
    alice.send_group(&to_bob, b"second".to_vec()).await.unwrap();
    bob_store.script([CommitOutcome::Failed], false);
    let outcome = bob.receive(0).await;
    assert!(
        matches!(outcome, Err(GroupError::Frozen)),
        "the acknowledgement of the first call could not commit: {:?}",
        outcome.map(|inbound| inbound.frozen)
    );
    assert!(bob.is_frozen());
    // Nothing of the second message was taken from the relay: after recovery it is delivered, with
    // the first event acknowledged by then.
    bob.recover().await.unwrap();
    let next = bob.receive(0).await.unwrap();
    let payloads: Vec<_> = next
        .events()
        .iter()
        .map(|event| event.payload.clone())
        .collect();
    assert_eq!(payloads, [b"second".to_vec()]);
}
