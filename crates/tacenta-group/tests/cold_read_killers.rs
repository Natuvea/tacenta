//! Cold-read killer tests (CR-07): each one pins a guard that a single-change
//! mutation of the branch at 75c9a20 left standing, and each passes on the
//! code and fails on its mutant. The IDs in the names are the mutant IDs of
//! the cold read's mutation table. They use only the public API.
use tacenta_group::*;

fn g() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}
fn m(name: &str) -> Member {
    Member::new(name.as_bytes().to_vec(), vec![1])
}
fn roster_with(
    revision: u64,
    pred: [u8; DIGEST_LEN],
    authority: Member,
    closed: bool,
    members: Vec<Member>,
) -> Roster {
    Roster::new(
        g(),
        revision,
        pred,
        authority,
        POLICY_VERSION_V1,
        closed,
        members,
    )
    .unwrap()
}
fn receiver_at(revision: u64) -> GroupReceiver {
    GroupReceiver::new(
        roster_with(
            revision,
            [0; 32],
            m("alice"),
            false,
            vec![m("alice"), m("bob"), m("carol")],
        ),
        [9; 32],
        m("bob"),
    )
}
fn ctx(
    revision: u64,
    digest: [u8; 32],
    sender: Member,
    recipient: Member,
    seq: u64,
) -> ApplicationContext {
    ApplicationContext::new(g(), revision, digest, sender, recipient, seq, b"x".to_vec()).unwrap()
}

// ---------------------------------------------------------------- receive
#[test]
fn gc_r02_wrong_recipient_is_refused() {
    let mut r = receiver_at(2);
    let c = ctx(2, [9; 32], m("alice"), m("carol"), 1);
    assert_eq!(
        r.receive(&c, &m("alice"), [1; 32]),
        ReceiveDisposition::Rejected(ReceiveRefusal::WrongRecipient)
    );
}
#[test]
fn gc_r05_old_revision_is_refused_not_deferred() {
    let mut r = receiver_at(2);
    let c = ctx(1, [9; 32], m("alice"), m("bob"), 1);
    assert_eq!(
        r.receive(&c, &m("alice"), [1; 32]),
        ReceiveDisposition::Rejected(ReceiveRefusal::OldRevision)
    );
}
#[test]
fn gc_r06_current_revision_with_wrong_roster_digest_is_refused() {
    let mut r = receiver_at(2);
    let c = ctx(2, [8; 32], m("alice"), m("bob"), 1);
    assert_eq!(
        r.receive(&c, &m("alice"), [1; 32]),
        ReceiveDisposition::Rejected(ReceiveRefusal::InvalidRoster)
    );
}
#[test]
fn gc_r11_wrong_group_is_refused() {
    let mut r = receiver_at(2);
    let other = GroupId::new(*b"another-group-id");
    let c = ApplicationContext::new(other, 2, [9; 32], m("alice"), m("bob"), 1, vec![]).unwrap();
    assert_eq!(
        r.receive(&c, &m("alice"), [1; 32]),
        ReceiveDisposition::Rejected(ReceiveRefusal::WrongGroup)
    );
}
#[test]
fn gc_r12_future_duplicate_with_a_changed_commitment_conflicts() {
    let mut r = receiver_at(2);
    let c = ctx(3, [1; 32], m("alice"), m("bob"), 1);
    assert_eq!(
        r.receive(&c, &m("alice"), [1; 32]),
        ReceiveDisposition::Deferred
    );
    assert_eq!(
        r.receive(&c, &m("alice"), [1; 32]),
        ReceiveDisposition::Deferred
    );
    assert_eq!(
        r.receive(&c, &m("alice"), [2; 32]),
        ReceiveDisposition::Rejected(ReceiveRefusal::Conflict)
    );
}
// R15 and R16 (the receiver-state count bounds) are killed in limits.rs, where
// a state with 513 accepted entries or five deferred contexts is otherwise valid.

// ------------------------------------------------------------- roster view
fn genesis_view() -> RosterView {
    RosterView::accept_genesis(
        &m("alice"),
        roster_with(0, [0; 32], m("alice"), false, vec![m("alice")]),
        [1; 32],
    )
    .unwrap()
}
#[test]
fn gc_v02_successor_must_name_the_accepted_digest_as_predecessor() {
    let mut v = genesis_view();
    let bad = roster_with(1, [7; 32], m("alice"), false, vec![m("alice"), m("bob")]);
    assert_eq!(
        v.accept_successor(&m("alice"), bad, [2; 32]),
        RosterDisposition::Rejected(RosterRefusal::MissingPredecessor)
    );
}
#[test]
fn gc_v04_a_closed_group_cannot_be_reopened() {
    let mut v = genesis_view();
    let closed = roster_with(1, [1; 32], m("alice"), true, vec![m("alice")]);
    assert_eq!(
        v.accept_successor(&m("alice"), closed, [2; 32]),
        RosterDisposition::Accepted
    );
    let reopened = roster_with(2, [2; 32], m("alice"), false, vec![m("alice")]);
    assert_eq!(
        v.accept_successor(&m("alice"), reopened, [3; 32]),
        RosterDisposition::Rejected(RosterRefusal::Reopened)
    );
}
#[test]
fn gc_v05_authority_cannot_change_in_place() {
    let mut v = genesis_view();
    let moved = roster_with(1, [1; 32], m("bob"), false, vec![m("alice"), m("bob")]);
    assert_eq!(
        v.accept_successor(&m("alice"), moved, [2; 32]),
        RosterDisposition::Rejected(RosterRefusal::AuthorityTransfer)
    );
}
#[test]
fn gc_v07_authority_must_remain_a_member() {
    let mut v = genesis_view();
    let without = roster_with(1, [1; 32], m("alice"), false, vec![m("bob")]);
    assert_eq!(
        v.accept_successor(&m("alice"), without, [2; 32]),
        RosterDisposition::Rejected(RosterRefusal::MissingAuthorityMember)
    );
}
#[test]
fn gc_v08_an_older_revision_is_stale_not_missing_predecessor() {
    let mut v = genesis_view();
    let r1 = roster_with(1, [1; 32], m("alice"), false, vec![m("alice"), m("bob")]);
    v.accept_successor(&m("alice"), r1, [2; 32]);
    let r2 = roster_with(2, [2; 32], m("alice"), false, vec![m("alice"), m("bob")]);
    v.accept_successor(&m("alice"), r2, [3; 32]);
    let old = roster_with(1, [1; 32], m("alice"), false, vec![m("alice"), m("bob")]);
    assert_eq!(
        v.accept_successor(&m("alice"), old, [2; 32]),
        RosterDisposition::Rejected(RosterRefusal::StaleRevision)
    );
}
#[test]
fn gc_v10_a_closed_group_has_no_active_members() {
    let mut v = genesis_view();
    let closed = roster_with(1, [1; 32], m("alice"), true, vec![m("alice"), m("bob")]);
    v.accept_successor(&m("alice"), closed, [2; 32]);
    assert!(!v.is_active(&m("alice")));
    assert!(!v.is_active(&m("bob")));
}
#[test]
fn gc_v12_checkpoint_restore_verifies_the_core_commitment() {
    let mut v = genesis_view();
    let r1 = roster_with(1, [1; 32], m("alice"), false, vec![m("alice"), m("bob")]);
    v.accept_successor(&m("alice"), r1, [2; 32]);
    let enc = v.encode_state().unwrap();
    assert_eq!(
        RosterView::decode_state(&enc, &m("alice"), |_| [3; 32]),
        Err(RosterRefusal::Conflict)
    );
}
#[test]
fn gc_v13_a_successor_for_another_group_is_refused() {
    let mut v = genesis_view();
    let other = Roster::new(
        GroupId::new(*b"another-group-id"),
        1,
        [1; 32],
        m("alice"),
        POLICY_VERSION_V1,
        false,
        vec![m("alice"), m("bob")],
    )
    .unwrap();
    assert_eq!(
        v.accept_successor(&m("alice"), other, [2; 32]),
        RosterDisposition::Rejected(RosterRefusal::WrongGroup)
    );
}

// -------------------------------------------------------------- invitations
fn inv(id: u8, target: Member, expires: u64) -> Invitation {
    Invitation::new(
        InvitationId::new([id; 16]),
        g(),
        target,
        0,
        [0; 32],
        POLICY_VERSION_V1,
        expires,
    )
    .unwrap()
}
#[test]
fn gc_i04_i06_i10_only_the_authority_can_create_revoke_or_admit() {
    let mut book = InvitationBook::new(g());
    assert_eq!(
        book.create(
            &m("bob"),
            &m("alice"),
            &[m("alice")],
            inv(1, m("bob"), 10),
            0
        )
        .map(|_| ()),
        Err(Error::Unauthorized)
    );
    book.create(
        &m("alice"),
        &m("alice"),
        &[m("alice")],
        inv(1, m("bob"), 10),
        0,
    )
    .unwrap();
    assert_eq!(
        book.revoke(InvitationId::new([1; 16]), &m("bob"), &m("alice"), 1)
            .map(|_| ()),
        Err(Error::Unauthorized)
    );
    book.accept(InvitationId::new([1; 16]), &m("bob"), 0, &[0; 32], 1)
        .unwrap();
    assert_eq!(
        book.admit(InvitationId::new([1; 16]), &m("bob"), &m("alice"), 1, 2)
            .map(|_| ()),
        Err(Error::Unauthorized)
    );
}
#[test]
fn gc_i07_an_existing_member_cannot_be_invited() {
    let mut book = InvitationBook::new(g());
    assert_eq!(
        book.create(
            &m("alice"),
            &m("alice"),
            &[m("alice"), m("bob")],
            inv(1, m("bob"), 10),
            0
        )
        .map(|_| ()),
        Err(Error::Conflict)
    );
}
#[test]
fn gc_i08_an_already_expired_invitation_is_refused_at_creation() {
    let mut book = InvitationBook::new(g());
    assert_eq!(
        book.create(
            &m("alice"),
            &m("alice"),
            &[m("alice")],
            inv(1, m("bob"), 10),
            10
        )
        .map(|_| ()),
        Err(Error::Expired)
    );
}
#[test]
fn gc_i09_the_invitation_book_holds_at_most_thirty_two_records() {
    let mut book = InvitationBook::new(g());
    for i in 0..32u8 {
        book.create(
            &m("alice"),
            &m("alice"),
            &[m("alice")],
            inv(i, m(&format!("t{i:02}")), 10),
            0,
        )
        .unwrap();
    }
    assert_eq!(
        book.create(
            &m("alice"),
            &m("alice"),
            &[m("alice")],
            inv(99, m("t99"), 10),
            0
        )
        .map(|_| ()),
        Err(Error::OutboxFull)
    );
}
#[test]
fn gc_i14_bootstrap_source_revision_must_match_its_roster() {
    let roster = roster_with(0, [0; 32], m("alice"), false, vec![m("alice")]);
    let mut i = inv(1, m("bob"), 10);
    i.source_revision = 5;
    assert_eq!(InvitationBootstrap::new(i, roster), Err(Error::Conflict));
}
#[test]
fn gc_i16_invitation_book_state_with_a_duplicate_id_is_refused() {
    let mut book = InvitationBook::new(g());
    book.create(
        &m("alice"),
        &m("alice"),
        &[m("alice")],
        inv(1, m("bob"), 10),
        0,
    )
    .unwrap();
    let one = book.encode_state().unwrap();
    let prefix = b"Tacenta Group Invitation Book State v1".len() + 16;
    let record = one[prefix + 1..].to_vec();
    let mut two = one[..prefix].to_vec();
    two.push(2);
    two.extend_from_slice(&record);
    two.extend_from_slice(&record);
    assert_eq!(
        InvitationBook::decode_state(&two, g()).map(|_| ()),
        Err(Error::NonCanonical)
    );
}
#[test]
fn gc_i17_an_admitted_invitation_cannot_be_revoked() {
    let mut book = InvitationBook::new(g());
    book.create(
        &m("alice"),
        &m("alice"),
        &[m("alice")],
        inv(1, m("bob"), 10),
        0,
    )
    .unwrap();
    book.accept(InvitationId::new([1; 16]), &m("bob"), 0, &[0; 32], 1)
        .unwrap();
    book.admit(InvitationId::new([1; 16]), &m("alice"), &m("alice"), 1, 2)
        .unwrap();
    assert_eq!(
        book.revoke(InvitationId::new([1; 16]), &m("alice"), &m("alice"), 3)
            .map(|_| ()),
        Err(Error::WrongDisposition)
    );
}

// ------------------------------------------------------------------- send
fn send_at(revision: u64) -> LogicalSend {
    let roster = roster_with(
        revision,
        [0; 32],
        m("alice"),
        false,
        vec![m("alice"), m("bob")],
    );
    LogicalSend::new(
        &roster,
        [5; 32],
        m("alice"),
        1,
        vec![m("bob")],
        b"hello".to_vec(),
    )
    .unwrap()
}
#[test]
fn gc_s03_a_send_at_the_new_revision_is_not_cancelled() {
    let mut s = send_at(2);
    s.cancel_for_newer_roster(2);
    assert_eq!(s.recipients()[0].disposition, RecipientDisposition::Pending);
}
#[test]
fn gc_s05_payload_cannot_be_substituted_under_one_logical_id() {
    let mut outbox = GroupOutbox::new(g());
    outbox.record(send_at(2)).unwrap();
    let roster = roster_with(2, [0; 32], m("alice"), false, vec![m("alice"), m("bob")]);
    let other = LogicalSend::new(
        &roster,
        [5; 32],
        m("alice"),
        1,
        vec![m("bob")],
        b"HELLO".to_vec(),
    )
    .unwrap();
    assert_eq!(outbox.record(other), Err(Error::Conflict));
}
#[test]
fn gc_s07_outbox_refuses_a_send_for_another_group() {
    let mut outbox = GroupOutbox::new(GroupId::new(*b"another-group-id"));
    assert_eq!(outbox.record(send_at(2)), Err(Error::Conflict));
}
#[test]
fn gc_s08_closed_roster_cannot_send() {
    let roster = roster_with(2, [0; 32], m("alice"), true, vec![m("alice"), m("bob")]);
    assert_eq!(
        LogicalSend::new(&roster, [5; 32], m("alice"), 1, vec![m("bob")], vec![]).map(|_| ()),
        Err(Error::Closed)
    );
}
#[test]
fn gc_s10_a_non_member_cannot_send() {
    let roster = roster_with(2, [0; 32], m("alice"), false, vec![m("alice"), m("bob")]);
    assert_eq!(
        LogicalSend::new(&roster, [5; 32], m("carol"), 1, vec![m("bob")], vec![]).map(|_| ()),
        Err(Error::NotMember)
    );
}
#[test]
fn gc_s14_a_cancelled_recipient_cannot_be_prepared_again() {
    let mut s = send_at(1);
    s.record_prepared(&m("bob"), [1; 32], vec![1, 2]).unwrap();
    s.cancel_for_newer_roster(2);
    assert_eq!(
        s.record_prepared(&m("bob"), [1; 32], vec![1, 2])
            .map(|_| ()),
        Err(Error::WrongDisposition)
    );
}

// ---------------------------------------------------------------- codecs
fn genesis_bytes() -> Vec<u8> {
    roster_with(0, [0; 32], m("alice"), false, vec![m("alice")])
        .encode()
        .unwrap()
}
#[test]
fn gc_l03_roster_decode_refuses_an_absurd_member_count_without_allocating_it() {
    let mut bytes = genesis_bytes();
    let alice_len = 4 + m("alice").identity().len() + 4 + m("alice").device().len();
    let count_at = bytes.len() - alice_len - 4;
    bytes.truncate(count_at + 4);
    bytes[count_at..].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(Roster::decode(&bytes), Err(Error::TooManyMembers));
}
#[test]
fn gc_l08_roster_closed_byte_must_be_zero_or_one() {
    let mut bytes = genesis_bytes();
    let alice_len = 4 + m("alice").identity().len() + 4 + m("alice").device().len();
    let closed_at = bytes.len() - alice_len - 4 - 1;
    bytes[closed_at] = 2;
    assert_eq!(Roster::decode(&bytes), Err(Error::Malformed));
}
#[test]
fn gc_l09_unknown_policy_version_is_refused() {
    assert_eq!(
        Roster::new(g(), 1, [0; 32], m("alice"), 2, false, vec![m("alice")]).map(|_| ()),
        Err(Error::UnsupportedPolicy)
    );
}
#[test]
fn gc_p02_payload_length_field_must_equal_the_value_length() {
    let mut bytes =
        GroupPayload::Roster(roster_with(0, [0; 32], m("alice"), false, vec![m("alice")]))
            .encode()
            .unwrap();
    let at = b"Tacenta Group Payload v1".len() + 1;
    let declared = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap());
    bytes[at..at + 4].copy_from_slice(&(declared + 1).to_be_bytes());
    assert_eq!(GroupPayload::decode(&bytes), Err(Error::Malformed));
}
