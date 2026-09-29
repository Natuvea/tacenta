//! Guards of the queue of held roster controls and its record (decision 0142,
//! `crates/tacenta-client/src/group_deferred_rosters.rs`): which held control is next for a view,
//! and which record `decode_record` refuses.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made.
//!
//! - R160: `next_for` returns any held control ahead of the view, not only its immediate successor.
//! - R161: `decode_record` accepts a record whose header names another group.
//! - R163: `decode_record` accepts a control of another group inside a record of this one.
//! - R165: `decode_record` accepts two controls for one revision.
//!
//! The ids (`R###`) are those of the single-change mutation run against 341e2b0.

use super::*;
use tacenta_core::crypto::groups::roster_commitment;
use tacenta_group::{DIGEST_LEN, POLICY_VERSION_V1};

fn group() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}

fn other_group() -> GroupId {
    GroupId::new(*b"another-group-id")
}

fn alice() -> Member {
    Member::new(b"alice".to_vec(), vec![1])
}

fn bob() -> Member {
    Member::new(b"bob".to_vec(), vec![1])
}

fn roster_of(
    group_id: GroupId,
    revision: u64,
    predecessor: [u8; DIGEST_LEN],
    members: Vec<Member>,
) -> Roster {
    Roster::new(
        group_id,
        revision,
        predecessor,
        alice(),
        POLICY_VERSION_V1,
        false,
        members,
    )
    .unwrap()
}

fn digest_of(roster: &Roster) -> [u8; DIGEST_LEN] {
    roster_commitment(&roster.encode().unwrap())
}

/// R160: in `DeferredRosters::next_for`, `Some(held.revision) == view.roster().revision + 1` becomes
/// `held.revision > view.roster().revision`, so a held control that is two or more revisions ahead
/// of the view (whose predecessor digest happens to be the view's) is offered as the successor.
/// The commit that applies it would refuse it and drop it from the queue.
#[test]
fn r160_a_held_control_two_revisions_ahead_is_not_the_successor_of_the_view() {
    let genesis = roster_of(group(), 0, [0; DIGEST_LEN], vec![alice()]);
    let view = RosterView::accept_source(&alice(), genesis.clone(), digest_of(&genesis)).unwrap();
    let mut queue = DeferredRosters::default();
    let ahead = roster_of(group(), 2, *view.digest(), vec![alice(), bob()]);
    assert_eq!(queue.hold(ahead), Hold::Held);
    assert_eq!(queue.next_for(&view), None);
    let next = roster_of(group(), 1, *view.digest(), vec![alice(), bob()]);
    assert_eq!(queue.hold(next.clone()), Hold::Held);
    assert_eq!(queue.next_for(&view), Some(&next));
}

/// R161: in `DeferredRosters::decode_record`, the check that the record's header names the group
/// the caller selected is removed. The earlier test only asserted that some error came back,
/// which a control of another group also produces.
#[test]
fn r161_a_record_for_another_group_is_malformed() {
    let mut queue = DeferredRosters::default();
    let held = roster_of(group(), 2, [7; DIGEST_LEN], vec![alice(), bob()]);
    assert_eq!(queue.hold(held), Hold::Held);
    let record = queue.encode_record(group()).unwrap();
    assert_eq!(
        DeferredRosters::decode_record(&record, other_group(), &alice()),
        Err(GroupError::Malformed)
    );
    let empty = DeferredRosters::default().encode_record(group()).unwrap();
    assert_eq!(
        DeferredRosters::decode_record(&empty, other_group(), &alice()),
        Err(GroupError::Malformed)
    );
}

/// R163: in `DeferredRosters::decode_record`, the check that each control belongs to the group of
/// the record is removed, so a record of this group may carry another group's control.
#[test]
fn r163_a_control_of_another_group_inside_a_record_is_not_canonical() {
    let foreign = roster_of(other_group(), 2, [7; DIGEST_LEN], vec![alice(), bob()]);
    let queue = DeferredRosters {
        rosters: vec![foreign],
    };
    let record = queue.encode_record(group()).unwrap();
    assert_eq!(
        DeferredRosters::decode_record(&record, group(), &alice()),
        Err(GroupError::NonCanonical)
    );
}

/// R165: in `DeferredRosters::decode_record`, `previous.revision >= roster.revision` becomes `>`, so
/// two controls for one revision are accepted. `hold` never produces such a queue; a damaged or
/// forged record could.
#[test]
fn r165_a_record_with_two_controls_for_one_revision_is_not_canonical() {
    let first = roster_of(group(), 2, [7; DIGEST_LEN], vec![alice(), bob()]);
    let second = roster_of(group(), 2, [8; DIGEST_LEN], vec![alice()]);
    let queue = DeferredRosters {
        rosters: vec![first, second],
    };
    let record = queue.encode_record(group()).unwrap();
    assert_eq!(
        DeferredRosters::decode_record(&record, group(), &alice()),
        Err(GroupError::NonCanonical)
    );
}

/// In `DeferredRosters::decode_record`, the `TCGQ` tag is not checked (any four bytes are
/// skipped), so a record of another kind of the same length and layout is read as a queue.
/// `recover_group_deferred_rosters` selects records by their tag, which is why nothing else notices.
#[test]
fn a_record_that_does_not_begin_with_the_queue_tag_is_malformed() {
    let mut queue = DeferredRosters::default();
    let held = roster_of(group(), 2, [7; DIGEST_LEN], vec![alice(), bob()]);
    assert_eq!(queue.hold(held), Hold::Held);
    let mut record = queue.encode_record(group()).unwrap();
    assert!(DeferredRosters::decode_record(&record, group(), &alice()).is_ok());
    record[..4].copy_from_slice(b"TCGX");
    assert_eq!(
        DeferredRosters::decode_record(&record, group(), &alice()),
        Err(GroupError::Malformed)
    );
}

/// In `DeferredRosters::decode_record`, the refusal of a record that declares more than
/// `MAX_DEFERRED_ROSTERS` controls is removed. The earlier test changed the count byte of a record
/// with four controls, which the truncation check refuses anyway. A record with five whole controls
/// would restore a queue longer than its bound, and `hold` (which refuses only at exactly four)
/// would then grow it without limit.
#[test]
fn a_record_with_five_whole_controls_is_malformed() {
    let five: Vec<Roster> = (2..=6)
        .map(|revision| roster_of(group(), revision, [7; DIGEST_LEN], vec![alice(), bob()]))
        .collect();
    let four = DeferredRosters {
        rosters: five[..4].to_vec(),
    };
    let record = four.encode_record(group()).unwrap();
    assert_eq!(
        DeferredRosters::decode_record(&record, group(), &alice()),
        Ok(four)
    );
    let too_many = DeferredRosters { rosters: five };
    let record = too_many.encode_record(group()).unwrap();
    assert_eq!(
        DeferredRosters::decode_record(&record, group(), &alice()),
        Err(GroupError::Malformed)
    );
}
