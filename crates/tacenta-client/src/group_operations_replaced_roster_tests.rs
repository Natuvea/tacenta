//! The checkpoint of the roster an accepted transition replaced (`TCGS`, decision 0145): what writes
//! it, what reads it, and that the bound on the control records never evicts it. The behaviour
//! through `GroupClient` with a stranger's flood is in `group_client::tests::stranger_traffic`.

use super::*;
use crate::operation_store::OperationSnapshot;
use tacenta_group::{GroupId, POLICY_VERSION_V1};

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

fn roster_in(
    group: GroupId,
    revision: u64,
    predecessor: [u8; 32],
    mut members: Vec<Member>,
) -> Roster {
    members.sort_by(Member::canonical_cmp);
    Roster::new(
        group,
        revision,
        predecessor,
        alice(),
        POLICY_VERSION_V1,
        false,
        members,
    )
    .unwrap()
}

fn digest_of(roster: &Roster) -> [u8; 32] {
    roster_commitment(&roster.encode().unwrap())
}

fn records(snapshot: &OperationSnapshot, tag: &[u8; 4]) -> Vec<Vec<u8>> {
    snapshot
        .group_controls
        .iter()
        .filter(|record| record.starts_with(tag))
        .cloned()
        .collect()
}

/// A view at revision 0 with `[alice]`, and the snapshot after accepting `[alice, bob]` at
/// revision 1 and `[alice]` at revision 2.
fn two_transitions() -> (RosterView, OperationSnapshot, [Roster; 3]) {
    let genesis = roster_in(gid(), 0, [0; 32], vec![alice()]);
    let mut view = RosterView::accept_genesis(&alice(), genesis.clone(), digest_of(&genesis))
        .expect("a genesis view");
    let r1 = roster_in(gid(), 1, digest_of(&genesis), vec![alice(), bob()]);
    let r2 = roster_in(gid(), 2, digest_of(&r1), vec![alice()]);
    let mut snapshot = OperationSnapshot::empty(1);
    for successor in [&r1, &r2] {
        assert_eq!(
            commit_roster_successor(
                &mut DiscardStore,
                &mut snapshot,
                &mut view,
                &alice(),
                successor.clone(),
                &mut [],
            ),
            Ok(RosterDisposition::Accepted)
        );
    }
    (view, snapshot, [genesis, r1, r2])
}

/// An accepted transition writes the replaced roster as a checkpoint, and the next accepted
/// transition replaces it: one record, for the roster the view held before the last transition.
#[test]
fn an_accepted_transition_replaces_the_checkpoint_with_the_roster_it_replaced() {
    let (view, snapshot, [_genesis, r1, _r2]) = two_transitions();
    let checkpoints = records(&snapshot, b"TCGS");
    assert_eq!(checkpoints.len(), 1);
    let preimage = r1.encode().unwrap();
    let mut expected = b"TCGS".to_vec();
    expected.extend_from_slice(gid().as_bytes());
    expected.extend_from_slice(&(preimage.len() as u32).to_be_bytes());
    expected.extend_from_slice(&preimage);
    assert_eq!(checkpoints[0], expected);
    assert_eq!(
        replaced_roster_members(&snapshot, &view),
        vec![alice(), bob()]
    );
}

/// A refusal and a repeat write no checkpoint, so they cannot move it.
#[test]
fn a_refused_or_repeated_successor_leaves_the_checkpoint_alone() {
    let (mut view, mut snapshot, [_genesis, _r1, r2]) = two_transitions();
    let before = records(&snapshot, b"TCGS");
    // The same roster again is a duplicate.
    assert_eq!(
        commit_roster_successor(
            &mut DiscardStore,
            &mut snapshot,
            &mut view,
            &alice(),
            r2.clone(),
            &mut [],
        ),
        Ok(RosterDisposition::Duplicate)
    );
    // A control from a member who is not the authority is refused.
    let r3 = roster_in(gid(), 3, digest_of(&r2), vec![alice(), bob()]);
    let refused = commit_roster_successor(
        &mut DiscardStore,
        &mut snapshot,
        &mut view,
        &bob(),
        r3,
        &mut [],
    );
    assert!(
        matches!(refused, Ok(RosterDisposition::Rejected(_))),
        "{refused:?}"
    );
    assert_eq!(records(&snapshot, b"TCGS"), before);
    assert_eq!(view.roster().revision, 2);
}

/// The read accepts the record only when it is the view's predecessor: another group's record, a
/// record whose roster is not the one the view names, a record with a wrong length or trailing
/// bytes, and a transcript record (`TCGC`) that holds the predecessor's preimage all yield nobody.
#[test]
fn the_replaced_roster_is_read_only_from_a_checkpoint_that_is_the_views_predecessor() {
    let (view, snapshot, [genesis, r1, _r2]) = two_transitions();
    let checkpoint = records(&snapshot, b"TCGS")[0].clone();
    let with = |records: Vec<Vec<u8>>| {
        let mut changed = OperationSnapshot::empty(1);
        changed.group_controls = records;
        replaced_roster_members(&changed, &view)
    };
    assert_eq!(with(vec![checkpoint.clone()]), vec![alice(), bob()]);
    assert!(with(Vec::new()).is_empty(), "no record");
    // The transcript's roster record is no longer read.
    let transcript = encode_roster_record(
        &r1.encode().unwrap(),
        &digest_of(&r1),
        RosterDisposition::Accepted,
    )
    .unwrap();
    assert!(with(vec![transcript]).is_empty());
    // The roster before the predecessor.
    let older = encode_replaced_roster_record(gid(), &genesis.encode().unwrap()).unwrap();
    assert!(with(vec![older]).is_empty());
    // Another group's record.
    let foreign = encode_replaced_roster_record(other_gid(), &r1.encode().unwrap()).unwrap();
    assert!(with(vec![foreign]).is_empty());
    // A record that names the group and holds a roster of another group.
    let mislabelled = encode_replaced_roster_record(
        gid(),
        &roster_in(other_gid(), 1, [9; 32], vec![alice(), bob()])
            .encode()
            .unwrap(),
    )
    .unwrap();
    assert!(with(vec![mislabelled]).is_empty());
    // Trailing bytes, a short body and a length that is too long.
    let mut trailing = checkpoint.clone();
    trailing.push(0);
    assert!(with(vec![trailing]).is_empty());
    let mut short = checkpoint.clone();
    short.pop();
    assert!(with(vec![short]).is_empty());
    let mut too_short = b"TCGS".to_vec();
    too_short.extend_from_slice(gid().as_bytes());
    too_short.extend_from_slice(&[0, 0]);
    assert!(with(vec![too_short]).is_empty());
    // The newest record of the group wins over an older one.
    assert_eq!(
        with(vec![
            encode_replaced_roster_record(gid(), &genesis.encode().unwrap()).unwrap(),
            checkpoint,
        ]),
        vec![alice(), bob()]
    );
}

/// The newest checkpoint of a group survives sixty-four later control records, and a checkpoint of
/// another group is a different checkpoint: it neither replaces the first nor is replaced by it.
#[test]
fn the_newest_replaced_roster_checkpoint_of_each_group_survives_eviction() {
    let mut snapshot = OperationSnapshot::empty(1);
    let mine = encode_replaced_roster_record(gid(), b"one").unwrap();
    let theirs = encode_replaced_roster_record(other_gid(), b"two").unwrap();
    append_group_control_records(&mut snapshot, [mine.clone(), theirs.clone()]);
    append_group_control_records(
        &mut snapshot,
        (0..MAX_GROUP_CONTROL_RECORDS as u8).map(|n| vec![b'T', b'C', b'G', b'E', n]),
    );
    assert_eq!(snapshot.group_controls.len(), MAX_GROUP_CONTROL_RECORDS);
    assert_eq!(records(&snapshot, b"TCGS"), vec![theirs.clone()]);
    // Only the newest record of the kind is exempt from eviction; the older group's is not.
    let newer = encode_replaced_roster_record(gid(), b"three").unwrap();
    let mut snapshot = OperationSnapshot::empty(1);
    append_group_control_records(&mut snapshot, [mine, theirs.clone(), newer.clone()]);
    assert_eq!(records(&snapshot, b"TCGS"), vec![theirs, newer]);
}
