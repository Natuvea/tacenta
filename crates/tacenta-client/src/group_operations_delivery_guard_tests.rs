//! Guards for the delivery cursor of decision 0144 (`group_operations.rs`): which `inbox` records
//! the cursor commit rewrites without their context, and what the rewritten record looks like.
//! They came from a mutation run of the second fix round, which found that no test pinned them.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc
//! comment is made.
//!
//! - `commit_delivery_cursor` scrubs only the first record that qualifies, or every accepted
//!   record with a context, delivered or not.
//! - The scrubbed record loses its effect byte, so its layout shifts.
//! - The acknowledgement is written under the generation it replaces.
//! - A record that does not decode, is not a `TCGR` receive record (a malformed-payload record),
//!   or belongs to a duplicate or refused item ends the scan of `undelivered_events` or of the
//!   scrub, so the events after it are hidden or keep their plaintext.

use super::*;
use tacenta_group::GroupId;

fn gid() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}

fn alice() -> Member {
    Member::new(b"alice-key".to_vec(), vec![1])
}

fn bob() -> Member {
    Member::new(b"bob-key".to_vec(), vec![1])
}

/// The accepted-event record of `payload` with `event_id`, as `record_receive` writes it (effect
/// `Unchanged`, commitment `[3; 32]`), and the context it holds.
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

/// The record of accepted event `event_id` after the cursor passed it: the layout of an accepted
/// record with an empty context (0144).
fn scrubbed_record(event_id: u64) -> Vec<u8> {
    encode_receive_record(
        CryptoStateEffect::Unchanged,
        &[],
        &[3; 32],
        ReceiveDisposition::Accepted { event_id },
    )
    .unwrap()
}

/// With events 0 to 4 in the inbox, between them a duplicate and a refusal, a
/// cursor at 3 rewrites the records of events 0, 1 and 2 to exactly the layout of an accepted
/// record with an empty context, and touches nothing else: the records of events 3 and 4 keep their
/// contexts and are what redelivery offers. A scrub that stops after the first record, one that
/// also empties events 3 and 4, one that writes a record of another layout, and one that writes the
/// acknowledgement under the generation of the snapshot it replaces each fail this test.
#[test]
fn the_cursor_commit_scrubs_exactly_the_delivered_records() {
    let events: Vec<(Vec<u8>, ApplicationContext)> = (0..5u64)
        .map(|id| accepted_record(id, format!("event {id}").as_bytes(), id))
        .collect();
    let duplicate = encode_receive_record(
        CryptoStateEffect::Unchanged,
        &[],
        &[3; 32],
        ReceiveDisposition::Duplicate { event_id: 1 },
    )
    .unwrap();
    let refused = encode_receive_record(
        CryptoStateEffect::Advanced,
        &[],
        &[4; 32],
        ReceiveDisposition::Rejected(ReceiveRefusal::NotActive),
    )
    .unwrap();
    let mut snapshot = OperationSnapshot::empty(1);
    snapshot.inbox = vec![
        events[0].0.clone(),
        duplicate.clone(),
        events[1].0.clone(),
        events[2].0.clone(),
        refused.clone(),
        events[3].0.clone(),
        events[4].0.clone(),
    ];
    commit_delivery_cursor(&mut DiscardStore, &mut snapshot, 3).unwrap();
    assert_eq!(snapshot.delivery_cursor, 3);
    assert_eq!(snapshot.generation, 2);
    assert_eq!(
        snapshot.inbox,
        vec![
            scrubbed_record(0),
            duplicate,
            scrubbed_record(1),
            scrubbed_record(2),
            refused,
            events[3].0.clone(),
            events[4].0.clone(),
        ]
    );
    assert_eq!(
        undelivered_events(&snapshot),
        vec![(3, events[3].1.clone()), (4, events[4].1.clone())]
    );
}

/// The records of the `inbox` that are not an accepted event with a context
/// (a malformed-payload record, which any peer that can message this device can cause; a duplicate;
/// a refused item; an accepted record whose context does not decode) are skipped, not the end of the
/// scan. With such records in front of and between the events, redelivery still offers every event
/// after them and the cursor commit still scrubs the delivered events after them.
#[test]
fn the_record_scans_skip_what_is_not_an_event() {
    let events: Vec<(Vec<u8>, ApplicationContext)> = [0u64, 2, 3]
        .into_iter()
        .map(|id| accepted_record(id, format!("event {id}").as_bytes(), id))
        .collect();
    let malformed =
        encode_malformed_record(CryptoStateEffect::Advanced, b"a payload that is nothing").unwrap();
    let duplicate = encode_receive_record(
        CryptoStateEffect::Unchanged,
        &[],
        &[3; 32],
        ReceiveDisposition::Duplicate { event_id: 0 },
    )
    .unwrap();
    let refused = encode_receive_record(
        CryptoStateEffect::Advanced,
        &[],
        &[4; 32],
        ReceiveDisposition::Rejected(ReceiveRefusal::NotActive),
    )
    .unwrap();
    let undecodable = encode_receive_record(
        CryptoStateEffect::Unchanged,
        b"not an application context",
        &[5; 32],
        ReceiveDisposition::Accepted { event_id: 1 },
    )
    .unwrap();
    let mut snapshot = OperationSnapshot::empty(1);
    snapshot.inbox = vec![
        malformed.clone(),
        events[0].0.clone(),
        duplicate.clone(),
        refused.clone(),
        undecodable,
        events[1].0.clone(),
        events[2].0.clone(),
    ];
    // Nothing is delivered yet: the three real events are offered, in order, past every kind of
    // record that is not one.
    assert_eq!(
        undelivered_events(&snapshot),
        vec![
            (0, events[0].1.clone()),
            (2, events[1].1.clone()),
            (3, events[2].1.clone()),
        ]
    );
    // The caller has events 0 and 2 and 3 (cursor 4): every accepted record with a context is
    // scrubbed, past the records in front of it.
    commit_delivery_cursor(&mut DiscardStore, &mut snapshot, 4).unwrap();
    let scrubbed_undecodable = encode_receive_record(
        CryptoStateEffect::Unchanged,
        &[],
        &[5; 32],
        ReceiveDisposition::Accepted { event_id: 1 },
    )
    .unwrap();
    assert_eq!(
        snapshot.inbox,
        vec![
            malformed,
            scrubbed_record(0),
            duplicate,
            refused,
            scrubbed_undecodable,
            scrubbed_record(2),
            scrubbed_record(3),
        ]
    );
    assert!(undelivered_events(&snapshot).is_empty());
}
