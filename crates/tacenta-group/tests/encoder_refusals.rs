//! An encoder makes the checks its decoder makes (open point 4 of
//! `spec/group-wire-formats.md`, decision 0149): a value the crate encodes is a
//! value the crate decodes, and a value the encoder refuses is refused with the
//! reason the decoder gives for the same fault, in the order the page states.
//!
//! Every value here is built through the public API. Several types have public
//! fields (`Invitation`, `InvitationBootstrap`, `Roster`, `LogicalMessageId`,
//! `LogicalSend::payload`), so a caller can hold a value that no constructor
//! would have produced; an encoder that trusts its constructor writes bytes that
//! the decoder then refuses. The vectors in `group_wire_vectors.rs` pin the same
//! faults byte for byte; these tests state them in Rust, with the ones a vector
//! cannot express (a private field, a local state).

use tacenta_group::*;

fn group() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}

fn member(identity: &[u8], device: &[u8]) -> Member {
    Member::new(identity.to_vec(), device.to_vec())
}

fn alice() -> Member {
    member(b"alice", &[1])
}

fn bob() -> Member {
    member(b"bob", &[1])
}

fn carol() -> Member {
    member(b"carol", &[1])
}

const DIGEST: [u8; DIGEST_LEN] = [7; DIGEST_LEN];

fn genesis() -> Roster {
    Roster::new(
        group(),
        0,
        [0; DIGEST_LEN],
        alice(),
        POLICY_VERSION_V1,
        false,
        vec![alice()],
    )
    .unwrap()
}

/// Revision 1 of the same group, with two members.
fn revision_one() -> Roster {
    Roster::new(
        group(),
        1,
        DIGEST,
        alice(),
        POLICY_VERSION_V1,
        false,
        vec![alice(), bob()],
    )
    .unwrap()
}

/// A bootstrap built from public fields, so that nothing checks it on the way.
fn bootstrap(target: Member) -> InvitationBootstrap {
    InvitationBootstrap {
        invitation: Invitation {
            id: InvitationId::new([9; 16]),
            group_id: group(),
            target,
            source_revision: 0,
            source_roster_digest: DIGEST,
            policy_version: POLICY_VERSION_V1,
            expires_at: 10,
            status: InvitationStatus::Pending,
        },
        source_roster: genesis(),
    }
}

// ---------------------------------------------------------------------------
// The invitation bootstrap
// ---------------------------------------------------------------------------

/// Open point 4: the encoder did not size-check the target, so a 300-byte
/// identity was written and the same crate then refused the bytes.
#[test]
fn a_bootstrap_target_over_the_size_limits_is_refused_at_encode() {
    let wide = bootstrap(member(&[3; MAX_IDENTITY_LEN + 1], b"d"));
    assert_eq!(wide.encode(), Err(Error::IdentityTooLarge));
    let long = bootstrap(member(b"bob", &[4; MAX_DEVICE_LEN + 1]));
    assert_eq!(long.encode(), Err(Error::DeviceTooLarge));
    // The identity is judged first, as the decoder does.
    let both = bootstrap(member(&[3; MAX_IDENTITY_LEN + 1], &[4; MAX_DEVICE_LEN + 1]));
    assert_eq!(both.encode(), Err(Error::IdentityTooLarge));
    // Far past the width of the target's own length prefix: still the size
    // refusal, not a framing one.
    let huge = bootstrap(member(&vec![3; 70_000], b"d"));
    assert_eq!(huge.encode(), Err(Error::IdentityTooLarge));
}

#[test]
fn a_bootstrap_target_at_the_size_limits_encodes_and_decodes() {
    let edge = bootstrap(member(&[3; MAX_IDENTITY_LEN], &[4; MAX_DEVICE_LEN]));
    let bytes = edge.encode().unwrap();
    assert_eq!(InvitationBootstrap::decode(&bytes), Ok(edge));
}

/// Open point 4: a reserved source revision or a policy version other than 1
/// was reported as `conflict` (or by the roster) where the decoder says
/// `reserved_revision` or `unsupported_policy`.
#[test]
fn a_reserved_revision_or_a_wrong_policy_is_named_as_such_at_encode() {
    let mut reserved = bootstrap(bob());
    reserved.invitation.source_revision = RESERVED_REVISION;
    assert_eq!(reserved.encode(), Err(Error::ReservedRevision));

    let mut policy = bootstrap(bob());
    policy.invitation.policy_version = 2;
    assert_eq!(policy.encode(), Err(Error::UnsupportedPolicy));
    policy.invitation.policy_version = 0;
    assert_eq!(policy.encode(), Err(Error::UnsupportedPolicy));

    // The source roster's own faults keep their reasons.
    let mut bad_roster = bootstrap(bob());
    bad_roster.source_roster.revision = RESERVED_REVISION;
    bad_roster.invitation.source_revision = RESERVED_REVISION;
    assert_eq!(bad_roster.encode(), Err(Error::ReservedRevision));
}

/// The decoder decodes the roster, then judges the invitation's own fields,
/// then how the two fit together; the encoder refuses in that order.
#[test]
fn a_bootstrap_with_several_faults_is_refused_as_the_decoder_refuses_it() {
    let unsorted = || {
        let mut roster = revision_one();
        roster.members.reverse();
        roster
    };
    let mut fits_badly = bootstrap(member(&[3; MAX_IDENTITY_LEN + 1], b"d"));
    fits_badly.invitation.group_id = GroupId::new([b'x'; 16]);
    // A target that is too large comes before a group that differs.
    assert_eq!(fits_badly.encode(), Err(Error::IdentityTooLarge));

    // The roster comes before the invitation's fields and before the fit.
    let mut roster_first = bootstrap(member(&[3; MAX_IDENTITY_LEN + 1], b"d"));
    roster_first.source_roster = unsorted();
    roster_first.invitation.source_revision = 1;
    roster_first.invitation.group_id = GroupId::new([b'x'; 16]);
    assert_eq!(roster_first.encode(), Err(Error::NonCanonical));

    // Reserved revision, then policy, then the target, then the fit.
    let mut reserved_and_policy = bootstrap(member(&[3; MAX_IDENTITY_LEN + 1], b"d"));
    reserved_and_policy.invitation.source_revision = RESERVED_REVISION;
    reserved_and_policy.invitation.policy_version = 2;
    assert_eq!(reserved_and_policy.encode(), Err(Error::ReservedRevision));
    let mut policy_and_target = bootstrap(member(&[3; MAX_IDENTITY_LEN + 1], b"d"));
    policy_and_target.invitation.policy_version = 2;
    assert_eq!(policy_and_target.encode(), Err(Error::UnsupportedPolicy));
    let mut reserved_and_group = bootstrap(bob());
    reserved_and_group.invitation.source_revision = RESERVED_REVISION;
    reserved_and_group.invitation.group_id = GroupId::new([b'x'; 16]);
    assert_eq!(reserved_and_group.encode(), Err(Error::ReservedRevision));
}

/// What only the encoder can see stays a conflict: the bytes carry no status,
/// and the group and revision of the invitation must be the roster's.
#[test]
fn a_bootstrap_that_does_not_fit_its_roster_or_is_not_pending_is_a_conflict() {
    let mut group_differs = bootstrap(bob());
    group_differs.invitation.group_id = GroupId::new([b'x'; 16]);
    assert_eq!(group_differs.encode(), Err(Error::Conflict));

    let mut revision_differs = bootstrap(bob());
    revision_differs.invitation.source_revision = 1;
    assert_eq!(revision_differs.encode(), Err(Error::Conflict));

    let mut revoked = bootstrap(bob());
    revoked.invitation.status = InvitationStatus::Revoked;
    assert_eq!(revoked.encode(), Err(Error::Conflict));
    // A field-level fault is still named first.
    revoked.invitation.target = member(&[3; MAX_IDENTITY_LEN + 1], b"d");
    assert_eq!(revoked.encode(), Err(Error::IdentityTooLarge));
}

/// `InvitationBootstrap::new` does not judge an invitation's own fields, so the
/// comparison with the roster is the only thing that refuses a policy version the
/// roster does not carry. The encoder reaches that policy through the invitation's
/// own check first and never through this comparison (it names the fault
/// `unsupported_policy`), so the constructor is pinned here.
#[test]
fn the_bootstrap_constructor_refuses_a_policy_version_the_roster_does_not_carry() {
    let mut invitation = bootstrap(bob()).invitation;
    invitation.policy_version = 2;
    assert_eq!(
        InvitationBootstrap::new(invitation, genesis()).err(),
        Some(Error::Conflict)
    );
}

#[test]
fn a_group_payload_refuses_a_bootstrap_its_encoder_refuses() {
    let wide = bootstrap(member(&[3; MAX_IDENTITY_LEN + 1], b"d"));
    assert_eq!(
        GroupPayload::InvitationBootstrap(wide).encode(),
        Err(Error::IdentityTooLarge)
    );
}

// ---------------------------------------------------------------------------
// The logical-send intent
// ---------------------------------------------------------------------------

/// A roster that lists `sender` and `recipients` (and nothing checks it):
/// `LogicalSend::new` reads only which members it lists.
fn listing(sender: &Member, recipients: &[Member]) -> Roster {
    let mut members = vec![sender.clone()];
    members.extend(recipients.iter().filter(|r| *r != sender).cloned());
    Roster {
        group_id: group(),
        revision: 1,
        predecessor_digest: [0; DIGEST_LEN],
        authority: sender.clone(),
        policy_version: POLICY_VERSION_V1,
        closed: false,
        members,
    }
}

fn send_to(sender: Member, recipients: Vec<Member>) -> LogicalSend {
    LogicalSend::new(
        &listing(&sender, &recipients),
        DIGEST,
        sender,
        3,
        recipients,
        b"hi".to_vec(),
    )
    .unwrap()
}

/// `n` distinct members in ascending order.
fn many(n: u8) -> Vec<Member> {
    (1..=n).map(|i| member(&[b'm', i], &[1])).collect()
}

/// Open point 4 for the intent: the page said the construction of a logical
/// send guarantees what the decoder checks. It does not for a member's size or
/// for the number of recipients, and a field of it is public.
#[test]
fn an_intent_with_a_member_over_the_size_limits_is_refused_at_encode() {
    let wide = member(&[9; MAX_IDENTITY_LEN + 1], b"d");
    let long = member(b"s", &[9; MAX_DEVICE_LEN + 1]);
    assert_eq!(
        send_to(wide.clone(), vec![bob()]).encode_intent(),
        Err(Error::IdentityTooLarge)
    );
    assert_eq!(
        send_to(long.clone(), vec![bob()]).encode_intent(),
        Err(Error::DeviceTooLarge)
    );
    // A recipient, first or last.
    assert_eq!(
        send_to(alice(), vec![member(b"b", &[9; MAX_DEVICE_LEN + 1])]).encode_intent(),
        Err(Error::DeviceTooLarge)
    );
    let mut last = many(7);
    last.push(member(&[0xff; MAX_IDENTITY_LEN + 1], b"d"));
    assert_eq!(
        send_to(alice(), last).encode_intent(),
        Err(Error::IdentityTooLarge)
    );
    // The edge encodes and decodes.
    let edge_sender = member(&[0xee; MAX_IDENTITY_LEN], &[0xee; MAX_DEVICE_LEN]);
    let edge = send_to(
        edge_sender,
        vec![member(&[1; MAX_IDENTITY_LEN], &[1; MAX_DEVICE_LEN])],
    );
    assert_eq!(
        LogicalSend::decode_intent(&edge.encode_intent().unwrap()),
        Ok(edge)
    );
}

#[test]
fn an_intent_to_more_than_eight_recipients_is_refused_at_encode() {
    assert_eq!(
        send_to(alice(), many(9)).encode_intent(),
        Err(Error::TooManyMembers)
    );
    let eight = send_to(alice(), many(8));
    assert_eq!(
        LogicalSend::decode_intent(&eight.encode_intent().unwrap()),
        Ok(eight)
    );
}

/// `payload` and `id` are public, so a value can change after `new` has judged it.
#[test]
fn an_intent_changed_after_construction_is_refused_at_encode() {
    let mut fat = send_to(alice(), vec![bob()]);
    fat.payload = vec![0; MAX_PAYLOAD_LEN + 1];
    assert_eq!(fat.encode_intent(), Err(Error::PayloadTooLarge));
    fat.payload = vec![0; MAX_PAYLOAD_LEN];
    assert_eq!(
        LogicalSend::decode_intent(&fat.encode_intent().unwrap()),
        Ok(fat)
    );

    let mut reserved = send_to(alice(), vec![bob()]);
    reserved.id.revision = RESERVED_REVISION;
    assert_eq!(reserved.encode_intent(), Err(Error::ReservedRevision));

    let mut wide = send_to(alice(), vec![bob()]);
    wide.id.sender = member(&[9; MAX_IDENTITY_LEN + 1], b"d");
    assert_eq!(wide.encode_intent(), Err(Error::IdentityTooLarge));
}

/// The encoder checks in the order the decoder meets the faults: the sender's
/// size, the payload, the recipient count, each recipient's size in turn, and
/// the revision last.
#[test]
fn an_intent_with_several_faults_is_refused_as_the_decoder_refuses_it() {
    let wide = member(&[9; MAX_IDENTITY_LEN + 1], b"d");

    // The sender's size before the payload.
    let mut sender_and_payload = send_to(wide.clone(), vec![bob()]);
    sender_and_payload.payload = vec![0; MAX_PAYLOAD_LEN + 1];
    assert_eq!(
        sender_and_payload.encode_intent(),
        Err(Error::IdentityTooLarge)
    );

    // The payload before the number of recipients.
    let mut payload_and_count = send_to(alice(), many(9));
    payload_and_count.payload = vec![0; MAX_PAYLOAD_LEN + 1];
    assert_eq!(
        payload_and_count.encode_intent(),
        Err(Error::PayloadTooLarge)
    );

    // The number of recipients before any recipient's size.
    let mut nine_and_wide = many(8);
    nine_and_wide.push(member(&[0xff; MAX_IDENTITY_LEN + 1], b"d"));
    assert_eq!(
        send_to(alice(), nine_and_wide).encode_intent(),
        Err(Error::TooManyMembers)
    );

    // The payload before the revision, which is judged last.
    let mut payload_and_revision = send_to(alice(), vec![bob()]);
    payload_and_revision.payload = vec![0; MAX_PAYLOAD_LEN + 1];
    payload_and_revision.id.revision = RESERVED_REVISION;
    assert_eq!(
        payload_and_revision.encode_intent(),
        Err(Error::PayloadTooLarge)
    );
}

// ---------------------------------------------------------------------------
// The local states: outside the page, but the same rule
// ---------------------------------------------------------------------------

/// `InvitationBook::create` takes an `Invitation` with public fields and does
/// not judge them, so a book can hold what `decode_state` refuses.
#[test]
fn an_invitation_book_holding_a_refused_record_is_refused_at_encode_state() {
    let refused = |edit: fn(&mut Invitation)| {
        let mut invitation = Invitation::new(
            InvitationId::new([9; 16]),
            group(),
            bob(),
            0,
            DIGEST,
            POLICY_VERSION_V1,
            10,
        )
        .unwrap();
        edit(&mut invitation);
        let mut book = InvitationBook::new(group());
        book.create(&alice(), &alice(), &[alice()], invitation, 0)
            .unwrap();
        book.encode_state()
    };
    assert_eq!(
        refused(|i| i.target = member(&[3; MAX_IDENTITY_LEN + 1], b"d")),
        Err(Error::IdentityTooLarge)
    );
    assert_eq!(
        refused(|i| i.target = member(b"bob", &[4; MAX_DEVICE_LEN + 1])),
        Err(Error::DeviceTooLarge)
    );
    assert_eq!(
        refused(|i| i.source_revision = RESERVED_REVISION),
        Err(Error::ReservedRevision)
    );
    assert_eq!(
        refused(|i| i.policy_version = 2),
        Err(Error::UnsupportedPolicy)
    );
    // The decoder reads the admitted revision with the status, before it
    // judges the record's fields; the encoder refuses in the same order.
    assert_eq!(
        refused(|i| {
            i.status = InvitationStatus::Admitted {
                revision: RESERVED_REVISION,
            };
            i.policy_version = 2;
        }),
        Err(Error::ReservedRevision)
    );
    // A record the decoder accepts still encodes, and comes back.
    let ok = refused(|_| {}).unwrap();
    assert!(InvitationBook::decode_state(&ok, group()).is_ok());
}

/// `GroupReceiver::new` takes the local member as given.
#[test]
fn a_receiver_whose_local_member_is_over_the_size_limits_is_refused_at_encode_state() {
    let receiver = |local: Member| GroupReceiver::new(revision_one(), DIGEST, local);
    assert_eq!(
        receiver(member(&[3; MAX_IDENTITY_LEN + 1], b"d")).encode_state(),
        Err(Error::IdentityTooLarge)
    );
    assert_eq!(
        receiver(member(b"bob", &[4; MAX_DEVICE_LEN + 1])).encode_state(),
        Err(Error::DeviceTooLarge)
    );
    // The roster comes first: the decoder decodes it before the local member.
    let mut bad_roster = revision_one();
    bad_roster.revision = RESERVED_REVISION;
    assert_eq!(
        GroupReceiver::new(bad_roster, DIGEST, member(&[3; MAX_IDENTITY_LEN + 1], b"d"))
            .encode_state(),
        Err(Error::ReservedRevision)
    );
    let bytes = receiver(bob()).encode_state().unwrap();
    assert!(GroupReceiver::decode_state(&bytes, |_| DIGEST, |_| DIGEST).is_ok());
    // Not a member of the roster is a valid terminal state, not a fault.
    assert!(receiver(carol()).encode_state().is_ok());
}
