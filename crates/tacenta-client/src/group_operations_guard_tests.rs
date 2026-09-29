//! Unit-level guards of private functions of `group_operations`
//! (`crates/tacenta-client/src/group_operations.rs`): which control records survive eviction, the
//! highest cancellation revision wins, the admission and control checks of a roster commit, the
//! durable refusal codes, a truncated record is refused, and the latest checkpoint of each kind is
//! the one restored.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made, and states that change. For M067, M095, M096 and M097 the guarded behaviour is
//! equivalent in practice when driven through the coordinator, so the guard is pinned here on the
//! private function itself.
//!
//! - M070 (`group_operations.rs:2084`), M071 (`:2087`), M073 (`:2089`): eviction in
//!   `append_group_control_records`.
//! - M067 (`group_operations.rs:2119`): `latest_group_outbox_cancellation` takes the last record,
//!   not the highest revision.
//! - M083 (`group_operations.rs:192`), M084 (`:1805`), M085 (`:1827`), M086 (`:1862`), M087
//!   (`:1848`): admission and control checks in `commit_roster_transition`.
//! - M089 (`group_operations.rs:2221`), M090 (`:2329`): durable refusal codes.
//! - M094 (`group_operations.rs:1964`): a truncated `TCG` record.
//! - M095 (`group_operations.rs:380`), M096 (`:400`), M097 (`:416`): the latest checkpoint of a
//!   kind is restored.
//! - M098 (`group_operations.rs:2414`): the declared length of a control outbox record.
//!
//! The ids (`M###`, `D##`) are those of the single-change mutation run against 97689a0; the
//! `file:line` in each test's doc comment is the change site at that commit.

use super::*;
use crate::operation_store::OperationSnapshot;
use tacenta_group::{GroupId, POLICY_VERSION_V1, RecipientDisposition};

fn gid() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}

fn alice() -> Member {
    Member::new(b"alice-key".to_vec(), vec![1])
}

fn bob() -> Member {
    Member::new(b"bob-key".to_vec(), vec![1])
}

fn carol() -> Member {
    Member::new(b"carol-key".to_vec(), vec![1])
}

fn roster(revision: u64, predecessor: [u8; 32], mut members: Vec<Member>) -> Roster {
    members.sort_by(Member::canonical_cmp);
    Roster::new(
        gid(),
        revision,
        predecessor,
        alice(),
        POLICY_VERSION_V1,
        false,
        members,
    )
    .unwrap()
}

fn rec(tag: &[u8; 4], n: u8) -> Vec<u8> {
    let mut record = tag.to_vec();
    record.push(n);
    record
}

/// A genesis view and receiver, and a book holding one invitation of Bob's that
/// he has accepted.
fn admission_fixture() -> (RosterView, GroupReceiver, InvitationBook, [u8; 32]) {
    let genesis = roster(0, [0; 32], vec![alice()]);
    let commitment = roster_commitment(&genesis.encode().unwrap());
    let view = RosterView::accept_genesis(&alice(), genesis.clone(), commitment).unwrap();
    let receiver = GroupReceiver::new(genesis, commitment, alice());
    let mut book = InvitationBook::new(gid());
    let invitation = Invitation::new(
        InvitationId::new([7; 16]),
        gid(),
        bob(),
        0,
        commitment,
        POLICY_VERSION_V1,
        10,
    )
    .unwrap();
    book.create(&alice(), &alice(), &[alice()], invitation, 0)
        .unwrap();
    book.accept(InvitationId::new([7; 16]), &bob(), 0, &commitment, 1)
        .unwrap();
    (view, receiver, book, commitment)
}

// ---- M070, M071, M073: which control records survive eviction ---------------

/// M070 (`group_operations.rs:2084`): `append_group_control_records` scans `.enumerate().rev()` for
/// the record to evict, so it drops the newest evictable record (the one just appended) rather than
/// the oldest.
#[test]
fn m070_eviction_drops_the_oldest_evictable_record() {
    let mut snapshot = OperationSnapshot::empty(1);
    append_group_control_records(
        &mut snapshot,
        (0..MAX_GROUP_CONTROL_RECORDS as u8).map(|n| rec(b"TCGE", n)),
    );
    assert_eq!(snapshot.group_controls.len(), MAX_GROUP_CONTROL_RECORDS);
    append_group_control_records(&mut snapshot, [rec(b"TCGE", 200)]);
    assert_eq!(snapshot.group_controls.len(), MAX_GROUP_CONTROL_RECORDS);
    assert!(!snapshot.group_controls.contains(&rec(b"TCGE", 0)));
    assert!(snapshot.group_controls.contains(&rec(b"TCGE", 1)));
    assert_eq!(snapshot.group_controls.last(), Some(&rec(b"TCGE", 200)));
}

/// M071 (`group_operations.rs:2087`): the exemption of the newest `TCGV` (roster view) record from
/// eviction is removed. The newest checkpoint sits before sixty-four other records.
#[test]
fn m071_the_newest_roster_view_checkpoint_survives_eviction() {
    let mut snapshot = OperationSnapshot::empty(1);
    append_group_control_records(&mut snapshot, [rec(b"TCGV", 1)]);
    append_group_control_records(
        &mut snapshot,
        (0..MAX_GROUP_CONTROL_RECORDS as u8).map(|n| rec(b"TCGE", n)),
    );
    assert_eq!(snapshot.group_controls.len(), MAX_GROUP_CONTROL_RECORDS);
    assert_eq!(snapshot.group_controls[0], rec(b"TCGV", 1));
}

/// M073 (`group_operations.rs:2089`): the same for the newest `TCGO` (control outbox) record.
#[test]
fn m073_the_newest_control_outbox_checkpoint_survives_eviction() {
    let mut snapshot = OperationSnapshot::empty(1);
    append_group_control_records(&mut snapshot, [rec(b"TCGO", 1)]);
    append_group_control_records(
        &mut snapshot,
        (0..MAX_GROUP_CONTROL_RECORDS as u8).map(|n| rec(b"TCGE", n)),
    );
    assert_eq!(snapshot.group_controls.len(), MAX_GROUP_CONTROL_RECORDS);
    assert_eq!(snapshot.group_controls[0], rec(b"TCGO", 1));
}

// ---- M067: the highest recorded cancellation revision wins ------------------

/// M067 (`group_operations.rs:2119`): `latest = Some(latest.unwrap_or(0).max(revision))` becomes
/// `latest = Some(revision)`, so the last record wins whatever its revision.
#[test]
fn m067_the_highest_cancellation_revision_wins_not_the_last_record() {
    let mut snapshot = OperationSnapshot::empty(1);
    snapshot.group_controls = vec![
        encode_group_outbox_cancellation_record(gid(), 5),
        encode_group_outbox_cancellation_record(gid(), 3),
        encode_group_outbox_cancellation_record(GroupId::new(*b"another-group-id"), 9),
    ];
    assert_eq!(
        latest_group_outbox_cancellation(&snapshot, gid()),
        Ok(Some(5))
    );
}

// ---- M083..M087: the commit's own admission and control checks --------------

/// M083 (`group_operations.rs:192`): `admission_is_revoked` also treats an Expired invitation as
/// revoked.
#[test]
fn m083_an_expired_invitation_is_not_a_revoked_one() {
    let (view, _, mut book, commitment) = admission_fixture();
    // Now past the expiry: the (failed) acceptance moves the record to Expired.
    let _ = book.accept(InvitationId::new([7; 16]), &bob(), 0, &commitment, 10);
    assert_eq!(book.records()[0].status, InvitationStatus::Expired);
    let successor = roster(1, *view.digest(), vec![alice(), bob()]);
    let admission = InvitationAdmission {
        id: InvitationId::new([7; 16]),
        target: bob(),
        now: 10,
    };
    assert!(!admission_is_revoked(Some(&book), &successor, &admission));
}

/// M084 (`group_operations.rs:1805`): the loop over the passed logical sends no longer checks the
/// group, so a send of another group is cancelled by this group's accepted roster.
#[test]
fn m084_another_groups_send_is_not_cancelled_by_this_groups_roster() {
    let (mut view, mut receiver, _, _) = admission_fixture();
    let other = GroupId::new(*b"another-group-id");
    let genesis_other = Roster::new(
        other,
        0,
        [0; 32],
        alice(),
        POLICY_VERSION_V1,
        false,
        vec![alice()],
    )
    .unwrap();
    let foreign = LogicalSend::new(
        &genesis_other,
        [5; 32],
        alice(),
        0,
        vec![alice()],
        b"elsewhere".to_vec(),
    )
    .unwrap();
    let mut sends = [foreign];
    let successor = roster(1, *view.digest(), vec![alice(), bob()]);
    let mut snapshot = OperationSnapshot::empty(1);
    let commit = commit_roster_transition(
        &mut DiscardStore,
        &mut snapshot,
        RosterCommitState {
            view: &mut view,
            receiver: Some(&mut receiver),
            provider: None,
            group_outbox: None,
            control_outbox: None,
            prepared_control: None,
            invitation_book: None,
            admission: None,
            deferred: None,
        },
        &alice(),
        successor,
        &mut sends,
    )
    .unwrap();
    assert_eq!(commit.disposition, RosterDisposition::Accepted);
    assert_eq!(
        sends[0].recipients()[0].disposition,
        RecipientDisposition::Pending
    );
}

/// A view that has already accepted revision one ([alice, bob]).
fn view_at_revision_one() -> (RosterView, Roster) {
    let genesis = roster(0, [0; 32], vec![alice()]);
    let commitment = roster_commitment(&genesis.encode().unwrap());
    let mut view = RosterView::accept_genesis(&alice(), genesis, commitment).unwrap();
    let r1 = roster(1, *view.digest(), vec![alice(), bob()]);
    assert_eq!(
        view.accept_successor(
            &alice(),
            r1.clone(),
            roster_commitment(&r1.encode().unwrap())
        ),
        RosterDisposition::Accepted
    );
    (view, r1)
}

/// M085 (`group_operations.rs:1827`): `if disposition != RosterDisposition::Accepted { return
/// Err(Policy) }` before a prepared control is recorded is removed: a control is recorded for a
/// roster that was not accepted (here a Duplicate).
#[test]
fn m085_a_prepared_control_is_not_recorded_for_a_roster_that_was_not_accepted() {
    let (mut view, r1) = view_at_revision_one();
    let mut outbox = ControlOutbox::default();
    let mut snapshot = OperationSnapshot::empty(1);
    let payload = GroupPayload::Roster(r1.clone()).encode().unwrap();
    let result = commit_roster_transition(
        &mut DiscardStore,
        &mut snapshot,
        RosterCommitState {
            view: &mut view,
            receiver: None,
            provider: None,
            group_outbox: None,
            control_outbox: Some(&mut outbox),
            prepared_control: Some(PreparedControl {
                recipient: bob(),
                payload,
                ciphertext: vec![1, 2, 3],
            }),
            invitation_book: None,
            admission: None,
            deferred: None,
        },
        &alice(),
        r1,
        &mut [],
    );
    assert_eq!(result, Err(GroupOperationError::Policy));
    assert_eq!(outbox, ControlOutbox::default());
}

/// M086 (`group_operations.rs:1862`): the invitation lookup of an admission compares only the
/// invitation ID, not its target: an admission naming Carol admits the invitation that was issued
/// to Bob.
#[test]
fn m086_an_admission_must_name_the_invitations_own_target() {
    let (mut view, mut receiver, mut book, _) = admission_fixture();
    let successor = roster(1, *view.digest(), vec![alice(), bob(), carol()]);
    let mut snapshot = OperationSnapshot::empty(1);
    let result = commit_roster_transition(
        &mut DiscardStore,
        &mut snapshot,
        RosterCommitState {
            view: &mut view,
            receiver: Some(&mut receiver),
            provider: None,
            group_outbox: None,
            control_outbox: None,
            prepared_control: None,
            invitation_book: Some(&mut book),
            admission: Some(InvitationAdmission {
                id: InvitationId::new([7; 16]),
                target: carol(),
                now: 2,
            }),
            deferred: None,
        },
        &alice(),
        successor,
        &mut [],
    );
    assert_eq!(result, Err(GroupOperationError::Policy));
    assert_eq!(
        book.records()[0].status,
        InvitationStatus::AcceptedPendingAdmission
    );
    assert_eq!(view.roster().revision, 0);
}

/// M087 (`group_operations.rs:1848`): `disposition != Accepted ||` is removed from the admission
/// check: an admission is applied to the book although the roster (a Duplicate here) was not
/// accepted.
#[test]
fn m087_an_admission_is_not_applied_for_a_roster_that_was_not_accepted() {
    let (mut view, r1) = view_at_revision_one();
    let genesis_commitment =
        roster_commitment(&roster(0, [0; 32], vec![alice()]).encode().unwrap());
    let mut book = InvitationBook::new(gid());
    let invitation = Invitation::new(
        InvitationId::new([7; 16]),
        gid(),
        bob(),
        0,
        genesis_commitment,
        POLICY_VERSION_V1,
        10,
    )
    .unwrap();
    book.create(&alice(), &alice(), &[alice()], invitation, 0)
        .unwrap();
    book.accept(
        InvitationId::new([7; 16]),
        &bob(),
        0,
        &genesis_commitment,
        1,
    )
    .unwrap();
    let mut snapshot = OperationSnapshot::empty(1);
    let result = commit_roster_transition(
        &mut DiscardStore,
        &mut snapshot,
        RosterCommitState {
            view: &mut view,
            receiver: None,
            provider: None,
            group_outbox: None,
            control_outbox: None,
            prepared_control: None,
            invitation_book: Some(&mut book),
            admission: Some(InvitationAdmission {
                id: InvitationId::new([7; 16]),
                target: bob(),
                now: 2,
            }),
            deferred: None,
        },
        &alice(),
        r1,
        &mut [],
    );
    assert_eq!(result, Err(GroupOperationError::Policy));
    assert_eq!(
        book.records()[0].status,
        InvitationStatus::AcceptedPendingAdmission
    );
}

// ---- M089, M090: the durable refusal codes are pinned ---------------------------

/// M089 (`group_operations.rs:2221`): `ReceiveRefusal::Conflict => 9` becomes `=> 10`, colliding
/// with DeferredFull.
#[test]
fn m089_every_receive_refusal_has_its_own_durable_code() {
    let table = [
        (ReceiveRefusal::Malformed, 0u8),
        (ReceiveRefusal::WrongPeer, 1),
        (ReceiveRefusal::WrongGroup, 2),
        (ReceiveRefusal::WrongRecipient, 3),
        (ReceiveRefusal::NotActive, 4),
        (ReceiveRefusal::OldRevision, 5),
        (ReceiveRefusal::InvalidRoster, 6),
        (ReceiveRefusal::FutureOutOfRange, 7),
        (ReceiveRefusal::SequenceExpired, 8),
        (ReceiveRefusal::Conflict, 9),
        (ReceiveRefusal::DeferredFull, 10),
    ];
    for (refusal, code) in table {
        let record = encode_receive_record(
            CryptoStateEffect::Unchanged,
            &[],
            &[3; 32],
            ReceiveDisposition::Rejected(refusal),
        )
        .unwrap();
        assert_eq!(&record[record.len() - 2..], &[3, code], "{refusal:?}");
    }
}

/// M090 (`group_operations.rs:2329`): `RosterRefusal::InvalidSource => 10` becomes `=> 9`,
/// colliding with MissingAuthorityMember.
#[test]
fn m090_every_roster_refusal_has_its_own_durable_code() {
    let table = [
        (RosterRefusal::WrongAuthority, 0u8),
        (RosterRefusal::WrongGroup, 1),
        (RosterRefusal::InvalidGenesis, 2),
        (RosterRefusal::StaleRevision, 3),
        (RosterRefusal::MissingPredecessor, 4),
        (RosterRefusal::Conflict, 5),
        (RosterRefusal::AuthorityTransfer, 6),
        (RosterRefusal::PolicyChange, 7),
        (RosterRefusal::Reopened, 8),
        (RosterRefusal::MissingAuthorityMember, 9),
        (RosterRefusal::InvalidSource, 10),
    ];
    for (refusal, code) in table {
        let record =
            encode_roster_record(b"preimage", &[3; 32], RosterDisposition::Rejected(refusal))
                .unwrap();
        assert_eq!(&record[record.len() - 2..], &[2, code], "{refusal:?}");
    }
}

// ---- M094: a truncated TCG record is refused ------------------------------------

/// M094 (`group_operations.rs:1964`): the `entry.get(..4)` else-branch returns `Ok(None)` for every
/// short entry, including one that starts with the `TCG` prefix.
#[test]
fn m094_a_truncated_tcg_record_is_refused_and_other_short_entries_are_not_ours() {
    assert_eq!(outbox_record_id(b"TCG"), Err(GroupOperationError::Policy));
    assert_eq!(outbox_record_id(b"TC"), Ok(None));
    assert_eq!(outbox_record_id(b"xyz"), Ok(None));
    let mut snapshot = OperationSnapshot::empty(1);
    snapshot.outbox = vec![b"TCG".to_vec()];
    assert_eq!(
        recover_group_outbox(&snapshot, gid()),
        Err(GroupOperationError::Policy)
    );
}

// ---- M095, M096, M097, M098: the latest checkpoint of a kind is the one used -----

/// M095 (`group_operations.rs:380`): `recover_group_roster_view` scans from the front (no
/// `.rev()`), so with two TCGV records it restores the older one.
#[test]
fn m095_the_latest_roster_view_record_is_restored() {
    let genesis = roster(0, [0; 32], vec![alice()]);
    let commitment = roster_commitment(&genesis.encode().unwrap());
    let view0 = RosterView::accept_genesis(&alice(), genesis, commitment).unwrap();
    let mut view1 = view0.clone();
    let r1 = roster(1, *view0.digest(), vec![alice(), bob()]);
    assert_eq!(
        view1.accept_successor(
            &alice(),
            r1.clone(),
            roster_commitment(&r1.encode().unwrap())
        ),
        RosterDisposition::Accepted
    );
    let mut snapshot = OperationSnapshot::empty(1);
    snapshot.group_controls = vec![
        encode_roster_view_record(&view0.encode_state().unwrap()).unwrap(),
        encode_roster_view_record(&view1.encode_state().unwrap()).unwrap(),
    ];
    assert_eq!(recover_group_roster_view(&snapshot, &alice()), Ok(view1));
}

/// M096 (`group_operations.rs:400`): the same for `recover_group_invitation_book` (TCGB).
#[test]
fn m096_the_latest_invitation_book_record_is_restored() {
    let (_, _, book_with_one, _) = admission_fixture();
    let empty = InvitationBook::new(gid());
    let mut snapshot = OperationSnapshot::empty(1);
    snapshot.group_controls = vec![
        encode_invitation_book_record(&empty.encode_state().unwrap()).unwrap(),
        encode_invitation_book_record(&book_with_one.encode_state().unwrap()).unwrap(),
    ];
    assert_eq!(
        recover_group_invitation_book(&snapshot, gid()),
        Ok(book_with_one)
    );
}

/// M097 (`group_operations.rs:416`): the same for `recover_group_control_outbox` (TCGO).
#[test]
fn m097_the_latest_control_outbox_record_is_restored() {
    let empty = ControlOutbox::default();
    let mut with_entry = ControlOutbox::default();
    let payload = GroupPayload::Roster(roster(1, [0; 32], vec![alice(), bob()]))
        .encode()
        .unwrap();
    with_entry
        .record_prepared(bob(), payload, vec![1, 2, 3])
        .unwrap();
    let mut snapshot = OperationSnapshot::empty(1);
    snapshot.group_controls = vec![
        encode_control_outbox_record(&empty.encode_state().unwrap()).unwrap(),
        encode_control_outbox_record(&with_entry.encode_state().unwrap()).unwrap(),
    ];
    assert_eq!(recover_group_control_outbox(&snapshot), Ok(with_entry));
}

/// M098 (`group_operations.rs:2414`): `decode_control_outbox_record` no longer compares the
/// declared length with the bytes that follow it, so a record that claims more bytes than it holds
/// is decoded from the bytes it has.
#[test]
fn m098_a_control_outbox_record_with_a_wrong_declared_length_is_refused() {
    let state = ControlOutbox::default().encode_state().unwrap();
    let mut record = encode_control_outbox_record(&state).unwrap();
    assert_eq!(
        recover_group_control_outbox(&{
            let mut snapshot = OperationSnapshot::empty(1);
            snapshot.group_controls = vec![record.clone()];
            snapshot
        }),
        Ok(ControlOutbox::default())
    );
    record[7] += 1; // the declared length is one more than the bytes that follow
    let mut snapshot = OperationSnapshot::empty(1);
    snapshot.group_controls = vec![record];
    assert_eq!(
        recover_group_control_outbox(&snapshot),
        Err(GroupOperationError::Policy)
    );
}
