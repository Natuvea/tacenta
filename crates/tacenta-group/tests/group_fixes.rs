//! Regression tests for the roster order, invitation admission, stale send,
//! sequence and terminal receiver state fixes (decisions 0136 to 0139). Most fail
//! on the code at 75c9a20 and pass after the fix; the git history of this file and
//! of `src/` shows both states. Some are guards that hold before and after, and
//! pin behaviour a fix must not change. They use only the public API of
//! `tacenta-group`.

use tacenta_group::*;

fn group() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}

fn mk(identity: &[u8], device: &[u8]) -> Member {
    Member::new(identity.to_vec(), device.to_vec())
}

fn roster_at(revision: u64, authority: Member, closed: bool, members: Vec<Member>) -> Roster {
    Roster::new(
        group(),
        revision,
        [0; DIGEST_LEN],
        authority,
        POLICY_VERSION_V1,
        closed,
        members,
    )
    .unwrap()
}

fn try_roster(authority: Member, members: Vec<Member>) -> Result<Roster, Error> {
    Roster::new(
        group(),
        1,
        [0; DIGEST_LEN],
        authority,
        POLICY_VERSION_V1,
        false,
        members,
    )
}

// ---------------------------------------------------------------------------
// CR-12 (a): roster order is the (identity, device) pair (decision 0136)
// ---------------------------------------------------------------------------

#[test]
fn roster_order_is_the_identity_device_pair_not_the_concatenation() {
    // As pairs, ("a", [ff]) < ("ab", []) because "a" is a proper prefix of
    // "ab". As concatenations, "a\xff" > "ab".
    let first = mk(b"a", &[0xff]);
    let second = mk(b"ab", &[]);
    assert!(try_roster(first.clone(), vec![first.clone(), second.clone()]).is_ok());
    assert_eq!(
        try_roster(first.clone(), vec![second, first]),
        Err(Error::NonCanonical)
    );
}

#[test]
fn members_with_equal_concatenations_share_a_roster_in_pair_order() {
    // ("a", "bc") and ("ab", "c") both concatenate to "abc". They are two
    // distinct members and must be able to share a roster, in pair order.
    let first = mk(b"a", b"bc");
    let second = mk(b"ab", b"c");
    assert!(try_roster(first.clone(), vec![first.clone(), second.clone()]).is_ok());
    assert_eq!(
        try_roster(first.clone(), vec![second, first]),
        Err(Error::NonCanonical)
    );
}

#[test]
fn recipient_order_follows_the_same_pair_order() {
    let prefixed = mk(b"a", &[0xff]);
    let longer = mk(b"ab", &[]);
    let sender = mk(b"b", &[1]);
    let roster = roster_at(
        1,
        sender.clone(),
        false,
        vec![prefixed.clone(), longer.clone(), sender.clone()],
    );
    let send = |recipients: Vec<Member>| {
        LogicalSend::new(
            &roster,
            [9; DIGEST_LEN],
            sender.clone(),
            0,
            recipients,
            b"hi".to_vec(),
        )
    };
    let in_order = send(vec![prefixed.clone(), longer.clone()]).unwrap();
    assert_eq!(
        send(vec![longer.clone(), prefixed.clone()]).map(|_| ()),
        Err(Error::NonCanonical)
    );
    // Recovery applies the same rule to the immutable intent.
    let intent = in_order.encode_intent().unwrap();
    assert_eq!(LogicalSend::decode_intent(&intent), Ok(in_order));
}

// ---------------------------------------------------------------------------
// CR-12 (b): invitation creation and admission (decision 0137)
// ---------------------------------------------------------------------------

fn named(name: &str) -> Member {
    mk(name.as_bytes(), &[1])
}

fn invitation_at(id: u8, target: Member, source_revision: u64) -> Invitation {
    Invitation::new(
        InvitationId::new([id; 16]),
        group(),
        target,
        source_revision,
        [0; DIGEST_LEN],
        POLICY_VERSION_V1,
        100,
    )
    .unwrap()
}

fn eight_members() -> Vec<Member> {
    (0..8u8).map(|index| mk(&[b'm', index], &[1])).collect()
}

#[test]
fn an_invitation_for_a_ninth_member_is_refused() {
    let members = eight_members();
    let authority = members[0].clone();
    let mut book = InvitationBook::new(group());
    let result = book
        .create(
            &authority,
            &authority,
            &members,
            invitation_at(1, named("ninth"), 5),
            0,
        )
        .map(|_| ());
    assert_eq!(result, Err(Error::TooManyMembers));
    assert!(book.records().is_empty());
}

#[test]
fn a_seventh_member_may_still_invite_an_eighth() {
    let members = eight_members();
    let authority = members[0].clone();
    let mut book = InvitationBook::new(group());
    assert!(
        book.create(
            &authority,
            &authority,
            &members[..7],
            invitation_at(1, named("eighth"), 5),
            0,
        )
        .is_ok()
    );
}

#[test]
fn an_invitation_for_a_second_device_of_a_member_is_refused() {
    let members = eight_members();
    let authority = members[0].clone();
    let second_device = mk(&[b'm', 3], &[2]);
    let mut book = InvitationBook::new(group());
    let result = book
        .create(
            &authority,
            &authority,
            &members[..4],
            invitation_at(1, second_device, 5),
            0,
        )
        .map(|_| ());
    assert_eq!(result, Err(Error::Conflict));
    assert!(book.records().is_empty());
}

#[test]
fn a_retry_of_a_recorded_invitation_survives_a_roster_that_has_since_filled() {
    let members = eight_members();
    let authority = members[0].clone();
    let invitation = invitation_at(1, named("eighth"), 5);
    let mut book = InvitationBook::new(group());
    book.create(&authority, &authority, &members[..7], invitation.clone(), 0)
        .unwrap();
    // Another member took the eighth seat, so the roster is now full; the
    // exact retry of the recorded invitation still returns the record.
    let retried = book
        .create(&authority, &authority, &members, invitation, 1)
        .map(|record| record.status);
    assert_eq!(retried, Ok(InvitationStatus::Pending));
}

fn accepted_book(source_revision: u64) -> (InvitationBook, Member, Member) {
    let authority = named("alice");
    let target = named("bob");
    let mut book = InvitationBook::new(group());
    book.create(
        &authority,
        &authority,
        std::slice::from_ref(&authority),
        invitation_at(1, target.clone(), source_revision),
        0,
    )
    .unwrap();
    book.accept(
        InvitationId::new([1; 16]),
        &target,
        source_revision,
        &[0; DIGEST_LEN],
        1,
    )
    .unwrap();
    (book, authority, target)
}

#[test]
fn admission_at_or_before_the_invitation_source_revision_is_refused() {
    let (mut book, authority, _) = accepted_book(5);
    let id = InvitationId::new([1; 16]);
    for revision in [0, 4, 5] {
        assert_eq!(
            book.admit(id, &authority, &authority, revision, 2)
                .map(|_| ()),
            Err(Error::StaleSource),
            "revision {revision}"
        );
        assert_eq!(
            book.records()[0].status,
            InvitationStatus::AcceptedPendingAdmission
        );
    }
    assert_eq!(
        book.admit(id, &authority, &authority, 6, 2)
            .map(|record| record.status),
        Ok(InvitationStatus::Admitted { revision: 6 })
    );
}

#[test]
fn a_repeated_admission_returns_the_record_only_at_the_same_revision() {
    let (mut book, authority, _) = accepted_book(0);
    let id = InvitationId::new([1; 16]);
    book.admit(id, &authority, &authority, 1, 2).unwrap();
    assert_eq!(
        book.admit(id, &authority, &authority, 1, 3)
            .map(|record| record.status),
        Ok(InvitationStatus::Admitted { revision: 1 })
    );
    assert_eq!(
        book.admit(id, &authority, &authority, 2, 3).map(|_| ()),
        Err(Error::Conflict)
    );
    assert_eq!(
        book.records()[0].status,
        InvitationStatus::Admitted { revision: 1 }
    );
}

#[test]
fn acceptance_is_idempotent_before_and_after_admission() {
    // Decision 0137: the acceptance control is retried and may be resent after
    // a crash, so a repeat must return the committed record.
    let (mut book, authority, target) = accepted_book(0);
    let id = InvitationId::new([1; 16]);
    assert_eq!(
        book.accept(id, &target, 0, &[0; DIGEST_LEN], 2)
            .map(|record| record.status),
        Ok(InvitationStatus::AcceptedPendingAdmission)
    );
    book.admit(id, &authority, &authority, 1, 3).unwrap();
    assert_eq!(
        book.accept(id, &target, 0, &[0; DIGEST_LEN], 4)
            .map(|record| record.status),
        Ok(InvitationStatus::Admitted { revision: 1 })
    );
}

#[test]
fn the_successor_roster_carries_the_cap_and_one_device_rules_admission_needs() {
    // The book has no roster, so admission relies on Roster::new for these.
    let mut nine = eight_members();
    nine.push(mk(&[b'm', 8], &[1]));
    assert_eq!(
        try_roster(nine[0].clone(), nine).map(|_| ()),
        Err(Error::TooManyMembers)
    );
    let members = vec![named("alice"), mk(b"alice", &[2])];
    assert_eq!(
        try_roster(named("alice"), members).map(|_| ()),
        Err(Error::NonCanonical)
    );
}

// ---------------------------------------------------------------------------
// CR-12 (c) and (d): stale sends and sequence allocation (decision 0138)
// ---------------------------------------------------------------------------

fn send_at(revision: u64, sender: &Member, sequence: u64, payload: &[u8]) -> LogicalSend {
    let recipient = named("bob");
    let mut members = vec![sender.clone(), recipient.clone()];
    members.sort_by(|left, right| {
        left.identity()
            .cmp(right.identity())
            .then_with(|| left.device().cmp(right.device()))
    });
    let roster = roster_at(revision, sender.clone(), false, members);
    LogicalSend::new(
        &roster,
        [5; DIGEST_LEN],
        sender.clone(),
        sequence,
        vec![recipient],
        payload.to_vec(),
    )
    .unwrap()
}

#[test]
fn the_outbox_refuses_a_send_older_than_the_revision_it_applied() {
    let alice = named("alice");
    let mut outbox = GroupOutbox::new(group());
    outbox.cancel_for_newer_roster(2);
    assert_eq!(
        outbox.record(send_at(1, &alice, 0, b"late")),
        Err(Error::StaleRevision)
    );
    assert!(outbox.sends().is_empty());
    assert_eq!(
        outbox.record(send_at(2, &alice, 0, b"current")),
        Ok(OutboxDisposition::Inserted)
    );
    assert_eq!(
        outbox.record(send_at(3, &alice, 0, b"ahead")),
        Ok(OutboxDisposition::Inserted)
    );
}

#[test]
fn the_applied_revision_never_moves_back() {
    let alice = named("alice");
    let mut outbox = GroupOutbox::new(group());
    outbox.cancel_for_newer_roster(3);
    outbox.cancel_for_newer_roster(2);
    assert_eq!(
        outbox.record(send_at(2, &alice, 0, b"late")),
        Err(Error::StaleRevision)
    );
}

#[test]
fn an_exact_replay_of_a_retained_send_is_still_a_duplicate_after_the_roster_moves() {
    let alice = named("alice");
    let mut outbox = GroupOutbox::new(group());
    outbox.record(send_at(1, &alice, 0, b"first")).unwrap();
    outbox.cancel_for_newer_roster(2);
    assert_eq!(
        outbox.record(send_at(1, &alice, 0, b"first")),
        Ok(OutboxDisposition::Duplicate)
    );
    assert_eq!(
        outbox.record(send_at(1, &alice, 0, b"changed")),
        Err(Error::Conflict)
    );
}

#[test]
fn next_sequence_starts_at_zero_and_follows_the_highest_retained_send() {
    let alice = named("alice");
    let mut outbox = GroupOutbox::new(group());
    assert_eq!(outbox.next_sequence(1, &alice), Ok(0));
    outbox.record(send_at(1, &alice, 0, b"a")).unwrap();
    assert_eq!(outbox.next_sequence(1, &alice), Ok(1));
    outbox.record(send_at(1, &alice, 7, b"b")).unwrap();
    assert_eq!(outbox.next_sequence(1, &alice), Ok(8));
}

#[test]
fn sequences_are_allocated_per_revision_and_per_sender() {
    let alice = named("alice");
    let carol = named("carol");
    let mut outbox = GroupOutbox::new(group());
    outbox.record(send_at(1, &alice, 4, b"a")).unwrap();
    assert_eq!(outbox.next_sequence(1, &alice), Ok(5));
    assert_eq!(outbox.next_sequence(2, &alice), Ok(0));
    assert_eq!(outbox.next_sequence(1, &carol), Ok(0));
}

#[test]
fn a_new_send_must_use_a_sequence_above_every_retained_one() {
    let alice = named("alice");
    let mut outbox = GroupOutbox::new(group());
    outbox.record(send_at(1, &alice, 5, b"five")).unwrap();
    for sequence in [0, 3, 4] {
        assert_eq!(
            outbox.record(send_at(1, &alice, sequence, b"reused")),
            Err(Error::SequenceOrder),
            "sequence {sequence}"
        );
    }
    // The retained ID keeps its own rules: an exact replay is a duplicate and
    // changed data is a conflict, not an ordering error.
    assert_eq!(
        outbox.record(send_at(1, &alice, 5, b"five")),
        Ok(OutboxDisposition::Duplicate)
    );
    assert_eq!(
        outbox.record(send_at(1, &alice, 5, b"other")),
        Err(Error::Conflict)
    );
    assert_eq!(
        outbox.record(send_at(1, &alice, 6, b"six")),
        Ok(OutboxDisposition::Inserted)
    );
    // Another sender or another revision has its own counter.
    assert_eq!(
        outbox.record(send_at(1, &named("carol"), 0, b"carol")),
        Ok(OutboxDisposition::Inserted)
    );
    assert_eq!(
        outbox.record(send_at(2, &alice, 0, b"new revision")),
        Ok(OutboxDisposition::Inserted)
    );
}

#[test]
fn a_sequence_that_cannot_be_followed_reports_exhaustion() {
    let alice = named("alice");
    let mut outbox = GroupOutbox::new(group());
    outbox
        .record(send_at(1, &alice, u64::MAX, b"last"))
        .unwrap();
    assert_eq!(
        outbox.next_sequence(1, &alice),
        Err(Error::SequenceExhausted)
    );
    assert_eq!(
        outbox.record(send_at(1, &alice, u64::MAX, b"other")),
        Err(Error::Conflict)
    );
}

// ---------------------------------------------------------------------------
// CR-06: a removed member's or closed group's receiver state is recoverable
// (decision 0139)
// ---------------------------------------------------------------------------

const ROSTER_DIGEST: [u8; DIGEST_LEN] = [9; DIGEST_LEN];

fn roster_commitment(_: &[u8]) -> [u8; DIGEST_LEN] {
    ROSTER_DIGEST
}

fn payload_commitment(_: &[u8]) -> [u8; DIGEST_LEN] {
    [1; DIGEST_LEN]
}

fn context(revision: u64, sequence: u64) -> ApplicationContext {
    ApplicationContext::new(
        group(),
        revision,
        ROSTER_DIGEST,
        named("alice"),
        named("bob"),
        sequence,
        b"hello".to_vec(),
    )
    .unwrap()
}

fn bob_receiver_at_r2() -> GroupReceiver {
    let mut receiver = GroupReceiver::new(
        roster_at(2, named("alice"), false, vec![named("alice"), named("bob")]),
        ROSTER_DIGEST,
        named("bob"),
    );
    assert_eq!(
        receiver.receive(&context(2, 0), &named("alice"), [1; DIGEST_LEN]),
        ReceiveDisposition::Accepted { event_id: 0 }
    );
    receiver
}

fn restore(receiver: &GroupReceiver) -> Result<GroupReceiver, Error> {
    GroupReceiver::decode_state(
        &receiver.encode_state().unwrap(),
        roster_commitment,
        payload_commitment,
    )
}

#[test]
fn receiver_state_of_a_removed_member_round_trips_and_refuses_application_contexts() {
    let mut receiver = bob_receiver_at_r2();
    assert_eq!(receiver.status(), ReceiverStatus::Active);
    let successor = roster_at(3, named("alice"), false, vec![named("alice")]);
    receiver
        .install_accepted_roster(successor, ROSTER_DIGEST)
        .unwrap();
    assert_eq!(receiver.status(), ReceiverStatus::NotMember);

    let mut restored = restore(&receiver).expect("a removed member's state must be recoverable");
    assert_eq!(restored, receiver);
    assert_eq!(restored.status(), ReceiverStatus::NotMember);
    for revision in [2, 3, 4] {
        assert_eq!(
            restored.receive(&context(revision, 1), &named("alice"), [2; DIGEST_LEN]),
            ReceiveDisposition::Rejected(ReceiveRefusal::NotActive),
            "revision {revision}"
        );
    }
}

#[test]
fn receiver_state_of_a_closed_group_round_trips_and_refuses_application_contexts() {
    let mut receiver = bob_receiver_at_r2();
    let closed = roster_at(3, named("alice"), true, vec![named("alice"), named("bob")]);
    receiver
        .install_accepted_roster(closed, ROSTER_DIGEST)
        .unwrap();
    assert_eq!(receiver.status(), ReceiverStatus::Closed);

    let mut restored = restore(&receiver).expect("a closed group's state must be recoverable");
    assert_eq!(restored, receiver);
    assert_eq!(restored.status(), ReceiverStatus::Closed);
    assert_eq!(
        restored.receive(&context(3, 1), &named("alice"), [2; DIGEST_LEN]),
        ReceiveDisposition::Rejected(ReceiveRefusal::NotActive)
    );
}

#[test]
fn a_recovered_terminal_receiver_keeps_its_stable_event_counter_and_can_be_readmitted() {
    let mut receiver = bob_receiver_at_r2();
    receiver
        .install_accepted_roster(
            roster_at(3, named("alice"), false, vec![named("alice")]),
            ROSTER_DIGEST,
        )
        .unwrap();
    let mut restored = restore(&receiver).unwrap();
    restored
        .install_accepted_roster(
            roster_at(4, named("alice"), false, vec![named("alice"), named("bob")]),
            ROSTER_DIGEST,
        )
        .unwrap();
    assert_eq!(restored.status(), ReceiverStatus::Active);
    assert_eq!(
        restored.receive(&context(4, 0), &named("alice"), [3; DIGEST_LEN]),
        ReceiveDisposition::Accepted { event_id: 1 }
    );
}

#[test]
fn a_terminal_receiver_state_that_carries_entries_is_refused() {
    // Take a live state that holds an accepted entry, then mark its embedded
    // roster closed. A closed roster must carry no accepted entries.
    let live = bob_receiver_at_r2();
    let mut bytes = live.encode_state().unwrap();
    let roster_domain = b"Tacenta Group Roster v1".len();
    let receiver_domain = b"Tacenta Group Receiver State v1".len();
    let roster_start = receiver_domain + 4;
    let authority = named("alice");
    let closed_at = roster_start
        + roster_domain
        + 4
        + GROUP_ID_LEN
        + 8
        + 4
        + DIGEST_LEN
        + 4
        + authority.identity().len()
        + 4
        + authority.device().len()
        + 4;
    assert_eq!(
        bytes[closed_at], 0,
        "the offset must point at the closed byte"
    );
    bytes[closed_at] = 1;
    assert_eq!(
        GroupReceiver::decode_state(&bytes, roster_commitment, payload_commitment).map(|_| ()),
        Err(Error::NonCanonical)
    );
}
