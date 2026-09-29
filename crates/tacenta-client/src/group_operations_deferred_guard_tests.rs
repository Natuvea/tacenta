//! Unit-level guards of the functions decisions 0142 and 0144 added to `group_operations`
//! (`crates/tacenta-client/src/group_operations.rs`): applying a held roster control, the queue's
//! checkpoint record, and the events a snapshot still holds for the caller.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made, and states that change.
//!
//! - R130, R140: `commit_next_deferred_roster` leaves a control the view refused in the queue.
//! - R118, R119: `undelivered_events` offers an event ID twice, or in record order.
//! - R144, R145: `recover_group_deferred_rosters` reads the oldest queue record, or another group's.
//! - R146, R147, R148: `append_group_control_records` does not replace the previous queue
//!   checkpoint, replaces it across groups, or lets the eviction drop the newest one.
//!
//! The ids (`R###`) are those of the single-change mutation run against 341e2b0.

use super::*;
use tacenta_group::{GroupId, POLICY_VERSION_V1, RosterRefusal};

fn gid() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}

fn other_gid() -> GroupId {
    GroupId::new(*b"another-group-id")
}

fn alice() -> Member {
    Member::new(b"alice-key".to_vec(), vec![1])
}

fn bob() -> Member {
    Member::new(b"bob-key".to_vec(), vec![1])
}

fn rec(tag: &[u8; 4], n: u8) -> Vec<u8> {
    let mut record = tag.to_vec();
    record.push(n);
    record
}

/// The queue record of one held control of `group_id` at `revision`.
fn queue_record(group_id: GroupId, revision: u64) -> Vec<u8> {
    let mut queue = DeferredRosters::default();
    let held = Roster::new(
        group_id,
        revision,
        [7; 32],
        alice(),
        POLICY_VERSION_V1,
        false,
        vec![alice(), bob()],
    )
    .unwrap();
    assert_eq!(queue.hold(held), Hold::Held);
    queue.encode_record(group_id).unwrap()
}

/// R130 and R140: in `commit_next_deferred_roster` the control being applied is no longer removed
/// from the queue when the view refuses it (R130 in `commit_roster_transition`, R140 by leaving
/// `applying` unset). The caller applies held controls in a loop until this returns `None`, so a
/// control that stays would be applied, refused and kept again without end.
#[test]
fn r130_a_held_control_that_the_view_refuses_is_dropped_from_the_queue() {
    let genesis = Roster::new(
        gid(),
        0,
        [0; 32],
        alice(),
        POLICY_VERSION_V1,
        false,
        vec![alice()],
    )
    .unwrap();
    let commitment = roster_commitment(&genesis.encode().unwrap());
    let mut view = RosterView::accept_genesis(&alice(), genesis.clone(), commitment).unwrap();
    let mut receiver = GroupReceiver::new(genesis, commitment, alice());
    let mut outbox = GroupOutbox::new(gid());
    // Revision one names the view's digest as its predecessor, so it is the successor; but it
    // omits its own authority, which the view refuses when the control is applied.
    let unacceptable = Roster::new(
        gid(),
        1,
        commitment,
        alice(),
        POLICY_VERSION_V1,
        false,
        vec![bob()],
    )
    .unwrap();
    let mut queue = DeferredRosters::default();
    assert_eq!(queue.hold(unacceptable), Hold::Held);
    let mut snapshot = OperationSnapshot::empty(1);
    let applied = commit_next_deferred_roster(
        &mut DiscardStore,
        &mut snapshot,
        &mut view,
        &mut receiver,
        &mut outbox,
        &mut queue,
    )
    .unwrap()
    .expect("the held control is the successor of the view");
    assert_eq!(
        applied.disposition,
        RosterDisposition::Rejected(RosterRefusal::MissingAuthorityMember)
    );
    assert_eq!(view.roster().revision, 0);
    assert!(queue.rosters().is_empty(), "{:?}", queue.rosters());
    let again = commit_next_deferred_roster(
        &mut DiscardStore,
        &mut snapshot,
        &mut view,
        &mut receiver,
        &mut outbox,
        &mut queue,
    )
    .unwrap();
    assert!(again.is_none());
}

/// The accepted-event record of `payload` with `event_id`, as `record_receive` writes it.
fn accepted_record(sequence: u64, payload: &[u8], event_id: u64) -> (Vec<u8>, ApplicationContext) {
    let context = ApplicationContext::new(
        gid(),
        1,
        [7; 32],
        alice(),
        bob(),
        sequence,
        payload.to_vec(),
    )
    .unwrap();
    let record = encode_receive_record(
        CryptoStateEffect::Unchanged,
        &context.encode().unwrap(),
        &[3; 32],
        ReceiveDisposition::Accepted { event_id },
    )
    .unwrap();
    (record, context)
}

/// R118: in `undelivered_events`, the test that an event ID is not offered twice is removed, so two
/// records that carry one event ID are both returned.
#[test]
fn r118_an_event_id_recorded_twice_is_offered_once() {
    let (record, context) = accepted_record(0, b"one", 4);
    let mut snapshot = OperationSnapshot::empty(1);
    snapshot.inbox = vec![record.clone(), record];
    assert_eq!(undelivered_events(&snapshot), vec![(4, context)]);
}

/// R119: in `undelivered_events`, the events are returned in the order of their records instead of
/// their event IDs.
#[test]
fn r119_undelivered_events_are_offered_in_event_id_order() {
    let (late, late_context) = accepted_record(1, b"late", 5);
    let (early, early_context) = accepted_record(0, b"early", 2);
    let mut snapshot = OperationSnapshot::empty(1);
    snapshot.inbox = vec![late, early];
    assert_eq!(
        undelivered_events(&snapshot),
        vec![(2, early_context), (5, late_context)]
    );
}

/// R144: in `recover_group_deferred_rosters`, the oldest queue record is read instead of the newest.
#[test]
fn r144_the_newest_queue_record_is_the_one_restored() {
    let mut snapshot = OperationSnapshot::empty(1);
    snapshot.group_controls = vec![queue_record(gid(), 2), queue_record(gid(), 3)];
    let restored = recover_group_deferred_rosters(&snapshot, gid(), &alice()).unwrap();
    let revisions: Vec<u64> = restored
        .rosters()
        .iter()
        .map(|roster| roster.revision)
        .collect();
    assert_eq!(revisions, [3]);
}

/// R145: in `recover_group_deferred_rosters`, the group ID is dropped from the scope of the search,
/// so another group's newer queue record is read (and refused) instead of this group's.
#[test]
fn r145_another_groups_queue_record_is_not_read() {
    let mut snapshot = OperationSnapshot::empty(1);
    snapshot.group_controls = vec![queue_record(gid(), 2), queue_record(other_gid(), 5)];
    let restored = recover_group_deferred_rosters(&snapshot, gid(), &alice()).unwrap();
    let revisions: Vec<u64> = restored
        .rosters()
        .iter()
        .map(|roster| roster.revision)
        .collect();
    assert_eq!(revisions, [2]);
    let none =
        recover_group_deferred_rosters(&snapshot, GroupId::new(*b"third-group-idxx"), &alice());
    assert_eq!(none, Ok(DeferredRosters::default()));
}

/// R146: `CHECKPOINT_TAGS` no longer lists `TCGQ`, so a new queue checkpoint is added beside the
/// previous one instead of replacing it.
#[test]
fn r146_a_new_queue_checkpoint_replaces_the_previous_one() {
    let mut snapshot = OperationSnapshot::empty(1);
    append_group_control_records(&mut snapshot, [queue_record(gid(), 2)]);
    append_group_control_records(&mut snapshot, [queue_record(gid(), 3)]);
    let queues: Vec<&Vec<u8>> = snapshot
        .group_controls
        .iter()
        .filter(|record| record.starts_with(b"TCGQ"))
        .collect();
    assert_eq!(queues, [&queue_record(gid(), 3)]);
}

/// R147: in `append_group_control_records`, the queue checkpoint is scoped to its tag alone, so the
/// checkpoint of one group replaces that of another.
#[test]
fn r147_a_queue_checkpoint_replaces_only_the_one_of_its_own_group() {
    let mut snapshot = OperationSnapshot::empty(1);
    append_group_control_records(&mut snapshot, [queue_record(gid(), 2)]);
    append_group_control_records(&mut snapshot, [queue_record(other_gid(), 2)]);
    assert_eq!(
        snapshot.group_controls,
        [queue_record(gid(), 2), queue_record(other_gid(), 2)]
    );
}

/// R148: in `append_group_control_records`, the newest queue checkpoint (`TCGQ`) is no longer exempt
/// from eviction. The newest checkpoint sits before sixty-four other records.
#[test]
fn r148_the_newest_queue_checkpoint_survives_eviction() {
    let mut snapshot = OperationSnapshot::empty(1);
    let queue = queue_record(gid(), 2);
    append_group_control_records(&mut snapshot, [queue.clone()]);
    append_group_control_records(
        &mut snapshot,
        (0..MAX_GROUP_CONTROL_RECORDS as u8).map(|n| rec(b"TCGE", n)),
    );
    assert_eq!(snapshot.group_controls.len(), MAX_GROUP_CONTROL_RECORDS);
    assert_eq!(snapshot.group_controls[0], queue);
}

/// In `commit_next_deferred_roster`, the group outbox is not handed to the transition, so a
/// held control that is applied does not stop the sends of older revisions the way a control from the
/// wire does (`commit_group_payload_with_deferred` passes it). The coordinator drains the queue at
/// once after the view moves, so no incomplete send of the current revision can exist there; this
/// pins the function's own contract.
#[test]
fn a_held_control_that_is_applied_cancels_the_sends_of_older_revisions() {
    let base = Roster::new(
        gid(),
        1,
        [7; 32],
        alice(),
        POLICY_VERSION_V1,
        false,
        vec![alice(), bob()],
    )
    .unwrap();
    let commitment = roster_commitment(&base.encode().unwrap());
    let mut view = RosterView::accept_source(&alice(), base.clone(), commitment).unwrap();
    let mut receiver = GroupReceiver::new(base.clone(), commitment, alice());
    let mut outbox = GroupOutbox::new(gid());
    let send =
        LogicalSend::new(&base, commitment, alice(), 0, vec![bob()], b"hi".to_vec()).unwrap();
    let id = send.id.clone();
    outbox.record(send).unwrap();
    assert!(!outbox.send(&id).unwrap().is_terminal());
    let successor = Roster::new(
        gid(),
        2,
        commitment,
        alice(),
        POLICY_VERSION_V1,
        false,
        vec![alice(), bob()],
    )
    .unwrap();
    let mut queue = DeferredRosters::default();
    assert_eq!(queue.hold(successor), Hold::Held);
    let mut snapshot = OperationSnapshot::empty(1);
    let applied = commit_next_deferred_roster(
        &mut DiscardStore,
        &mut snapshot,
        &mut view,
        &mut receiver,
        &mut outbox,
        &mut queue,
    )
    .unwrap()
    .expect("the held control is the successor of the view");
    assert_eq!(applied.disposition, RosterDisposition::Accepted);
    assert!(
        outbox.send(&id).unwrap().is_terminal(),
        "the send of revision 1 was stopped by the applied revision 2"
    );
}
