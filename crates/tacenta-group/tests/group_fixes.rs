//! Regression tests for the cold-read findings CR-06 and CR-12 (decisions
//! 0127 to 0130). Each test fails on the code at 75c9a20 and passes after the
//! fix; the git history of this file and of `src/` shows both states. They use
//! only the public API of `tacenta-group`.

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
// CR-12 (a): roster order is the (identity, device) pair (decision 0127)
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
// CR-12 (b): invitation creation and admission (decision 0128)
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
    // Decision 0128: the acceptance control is retried and may be resent after
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
