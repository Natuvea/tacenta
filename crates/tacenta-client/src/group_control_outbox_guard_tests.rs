//! Bounds and decoding of the control outbox (`crates/tacenta-client/src/group_control_outbox.rs`):
//! a reservation or a cancellation that makes an entry terminal reclaims the oldest terminal one,
//! an identity of exactly the bound round-trips, `decode_state` refuses a repeated sequence and a
//! repeated recipient and payload, and entries that differ only by device are ordered by device.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made.
//!
//! - M109 (`group_control_outbox.rs:170`): `reserve` does not reclaim after the reservation that
//!   makes an entry terminal.
//! - M113 (`group_control_outbox.rs:191`): `cancel_non_revocation_for_recipient` does not reclaim.
//! - M115 (`group_control_outbox.rs:320`): `decode_state` refuses an identity of exactly the bound.
//! - M116 (`group_control_outbox.rs:33`): `canonical_order` ignores the device.
//! - M120, M121 (`group_control_outbox.rs:360`): one of the two halves of the duplicate test in
//!   `decode_state` is removed.
//!
//! The ids (`M###`, `D##`) are those of the single-change mutation run against 97689a0; the
//! `file:line` in each test's doc comment is the change site at that commit.

use super::*;
use tacenta_group::{DIGEST_LEN, GroupId, POLICY_VERSION_V1, Roster};

fn alice() -> Member {
    Member::new(b"alice".to_vec(), vec![1])
}

fn bob() -> Member {
    Member::new(b"bob".to_vec(), vec![1])
}

fn roster_payload(revision: u64) -> Vec<u8> {
    GroupPayload::Roster(
        Roster::new(
            GroupId::new(*b"bounded-group-id"),
            revision,
            [0; DIGEST_LEN],
            alice(),
            POLICY_VERSION_V1,
            false,
            vec![alice(), bob()],
        )
        .unwrap(),
    )
    .encode()
    .unwrap()
}

/// An outbox holding sixteen terminal entries for Alice (the bound) and one
/// live, prepared entry for Bob.
fn sixteen_terminal_and_one_live() -> (Outbox, Vec<u8>) {
    let mut outbox = Outbox::default();
    for revision in 1..=16u64 {
        outbox.handoffs.push(Handoff {
            recipient: alice(),
            payload: roster_payload(revision),
            ciphertext: vec![revision as u8],
            attempts_reserved: 1,
            disposition: Disposition::RelayAccepted,
            sequence: revision,
        });
    }
    let live = roster_payload(100);
    outbox
        .record_prepared(bob(), live.clone(), vec![100])
        .unwrap();
    assert_eq!(outbox.len_for_tests(), 17);
    assert!(outbox.encode_state().is_ok());
    (outbox, live)
}

/// M109 (`group_control_outbox.rs:170`): in `reserve`, `self.reclaim();` after `let reserved =
/// handoff.clone();` is removed, so the reservation that makes an entry terminal (the third,
/// `ExhaustedUnknown`) can leave seventeen terminal entries in memory, which `encode_state` then
/// refuses (`OutboxFull`) at the next checkpoint.
#[test]
fn m109_the_reservation_that_makes_an_entry_terminal_reclaims_the_oldest_terminal_one() {
    let (mut outbox, live) = sixteen_terminal_and_one_live();
    for _ in 0..3 {
        outbox.reserve(&bob(), &live).unwrap();
    }
    assert_eq!(
        outbox.handoff(&bob(), &live).unwrap().disposition,
        Disposition::ExhaustedUnknown
    );
    // Seventeen terminal entries: the oldest is dropped.
    assert_eq!(outbox.len_for_tests(), 16);
    assert!(outbox.handoff(&alice(), &roster_payload(1)).is_err());
    assert!(outbox.handoff(&alice(), &roster_payload(2)).is_ok());
    assert!(outbox.encode_state().is_ok());
}

/// M113 (`group_control_outbox.rs:191`): in `cancel_non_revocation_for_recipient`, the trailing
/// `self.reclaim();` is removed: cancelling a live entry can push the terminal count over sixteen
/// with no reclaim.
#[test]
fn m113_cancelling_a_live_entry_reclaims_the_oldest_terminal_one() {
    let (mut outbox, live) = sixteen_terminal_and_one_live();
    outbox.cancel_non_revocation_for_recipient(&bob());
    assert_eq!(
        outbox.handoff(&bob(), &live).unwrap().disposition,
        Disposition::Cancelled
    );
    assert_eq!(outbox.len_for_tests(), 16);
    assert!(outbox.handoff(&alice(), &roster_payload(1)).is_err());
    assert!(outbox.encode_state().is_ok());
}

/// M115 (`group_control_outbox.rs:320`): in `decode_state`, `identity.len() > MAX_IDENTITY_LEN`
/// becomes `>=`, so a recipient whose identity is exactly the 256-byte bound is refused.
#[test]
fn m115_a_recipient_identity_of_exactly_the_bound_round_trips_and_one_more_is_refused() {
    let payload = roster_payload(1);
    let edge = Member::new(vec![7; 256], vec![9; 64]);
    let mut outbox = Outbox::default();
    outbox
        .record_prepared(edge.clone(), payload.clone(), vec![1])
        .unwrap();
    let state = outbox.encode_state().unwrap();
    assert_eq!(Outbox::decode_state(&state), Ok(outbox));

    let too_long_identity = Member::new(vec![7; 257], vec![9]);
    let mut long = Outbox::default();
    long.record_prepared(too_long_identity, payload.clone(), vec![1])
        .unwrap();
    assert_eq!(
        Outbox::decode_state(&long.encode_state().unwrap()),
        Err(GroupError::Malformed)
    );
    let too_long_device = Member::new(vec![7], vec![9; 65]);
    let mut long = Outbox::default();
    long.record_prepared(too_long_device, payload, vec![1])
        .unwrap();
    assert_eq!(
        Outbox::decode_state(&long.encode_state().unwrap()),
        Err(GroupError::Malformed)
    );
}

fn entry(recipient: Member, payload: Vec<u8>, sequence: u64) -> Handoff {
    Handoff {
        recipient,
        payload,
        ciphertext: vec![sequence as u8],
        attempts_reserved: 1,
        disposition: Disposition::RelayAccepted,
        sequence,
    }
}

/// M120 (`group_control_outbox.rs:360`): in `decode_state`, `known.sequence == sequence ||` is
/// removed from the duplicate test, so two entries with one sequence (and different payloads) are
/// accepted.
#[test]
fn m120_two_entries_with_one_sequence_are_refused_on_decode() {
    let mut outbox = Outbox::default();
    outbox.handoffs.push(entry(bob(), roster_payload(1), 5));
    outbox.handoffs.push(entry(bob(), roster_payload(2), 5));
    let state = outbox.encode_state().unwrap();
    assert_eq!(Outbox::decode_state(&state), Err(GroupError::Malformed));
}

/// M121 (`group_control_outbox.rs:360`): in `decode_state`, the `(known.recipient == recipient &&
/// same commitment)` alternative is removed, so two entries for one recipient and payload (with
/// different sequences) are accepted. The earlier test
/// `a_control_outbox_state_with_a_repeated_sequence_or_handoff_is_refused` feeds one input that
/// violates both, so each guard alone leaves it green.
#[test]
fn m121_two_entries_for_one_recipient_and_payload_are_refused_on_decode() {
    let mut outbox = Outbox::default();
    outbox.handoffs.push(entry(bob(), roster_payload(1), 5));
    outbox.handoffs.push(entry(bob(), roster_payload(1), 6));
    let state = outbox.encode_state().unwrap();
    assert_eq!(Outbox::decode_state(&state), Err(GroupError::Malformed));
}

/// M116 (`group_control_outbox.rs:33`): in `canonical_order`, the final `.then_with(||
/// device.cmp(device))` is removed, so entries that differ only by device stay in insertion order.
#[test]
fn m116_entries_that_differ_only_by_device_are_ordered_by_device() {
    let payload = roster_payload(1);
    let mut outbox = Outbox::default();
    outbox
        .record_prepared(
            Member::new(b"same".to_vec(), vec![2]),
            payload.clone(),
            vec![1],
        )
        .unwrap();
    outbox
        .record_prepared(Member::new(b"same".to_vec(), vec![1]), payload, vec![2])
        .unwrap();
    let devices: Vec<Vec<u8>> = outbox
        .pending()
        .iter()
        .map(|handoff| handoff.recipient.device().to_vec())
        .collect();
    assert_eq!(devices, vec![vec![1], vec![2]]);
}
