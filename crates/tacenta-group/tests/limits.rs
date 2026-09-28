//! Pins every limit of the bounded profile with a literal (cold read CR-08).
//!
//! Each bound is checked at both edges, cap accepted and cap plus one
//! refused, with explicit numbers. Nothing here derives a number from a
//! `MAX_*` constant, so raising a constant, or a test that follows it, fails.
//! The private constants (`DEDUP_WINDOW`, the future queue, the state and
//! payload bounds, the invitation-record cap) are pinned by the unit tests in
//! their own modules and exercised here through the public API.
//!
//! Where an edge cannot be reached with a valid value, the test says so and
//! pins the derived worst case instead: the roster, context, receiver-state and
//! payload bounds all sit above what the member, identity, device and payload
//! bounds allow, so they only ever refuse an input before it is parsed.

use tacenta_group::*;

fn group() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}

/// A member whose identity is `identity_len` copies of `tag`.
fn wide(tag: u8, identity_len: usize, device_len: usize) -> Member {
    Member::new(vec![tag; identity_len], vec![tag; device_len])
}

fn small(name: &str) -> Member {
    Member::new(name.as_bytes().to_vec(), vec![1])
}

fn roster(revision: u64, authority: Member, members: Vec<Member>) -> Result<Roster, Error> {
    Roster::new(
        group(),
        revision,
        [0; DIGEST_LEN],
        authority,
        POLICY_VERSION_V1,
        false,
        members,
    )
}

fn members_of_width(count: u8, identity_len: usize, device_len: usize) -> Vec<Member> {
    (1..=count)
        .map(|tag| wide(tag, identity_len, device_len))
        .collect()
}

// ---------------------------------------------------------------------------
// The public constants themselves
// ---------------------------------------------------------------------------

#[test]
fn the_public_constants_have_the_documented_values() {
    assert_eq!(GROUP_ID_LEN, 16);
    assert_eq!(DIGEST_LEN, 32);
    assert_eq!(MAX_MEMBERS, 8);
    assert_eq!(MAX_PAYLOAD_LEN, 1_024);
    assert_eq!(MAX_IDENTITY_LEN, 256);
    assert_eq!(MAX_DEVICE_LEN, 64);
    assert_eq!(MAX_ROSTER_LEN, 4_096);
    assert_eq!(MAX_APPLICATION_CONTEXT_LEN, 2_048);
    assert_eq!(MAX_LIVE_LOGICAL_SENDS, 8);
    assert_eq!(POLICY_VERSION_V1, 1);
    assert_eq!(RESERVED_REVISION, u64::MAX);
}

#[test]
fn a_group_id_is_exactly_sixteen_bytes() {
    assert!(GroupId::try_from([0u8; 16].as_slice()).is_ok());
    assert_eq!(
        GroupId::try_from([0u8; 15].as_slice()),
        Err(Error::Malformed)
    );
    assert_eq!(
        GroupId::try_from([0u8; 17].as_slice()),
        Err(Error::Malformed)
    );
}

// ---------------------------------------------------------------------------
// Eight members
// ---------------------------------------------------------------------------

/// Mirrors `Roster::encode` for values the test wants to break on purpose.
fn raw_roster(
    revision: u64,
    authority: &Member,
    declared_count: u32,
    members: &[Member],
) -> Vec<u8> {
    fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    fn member(out: &mut Vec<u8>, member: &Member) {
        lp(out, member.identity());
        lp(out, member.device());
    }
    let mut out = b"Tacenta Group Roster v1".to_vec();
    lp(&mut out, group().as_bytes());
    out.extend_from_slice(&revision.to_be_bytes());
    lp(&mut out, &[0; DIGEST_LEN]);
    member(&mut out, authority);
    out.extend_from_slice(&1u32.to_be_bytes());
    out.push(0);
    out.extend_from_slice(&declared_count.to_be_bytes());
    for entry in members {
        member(&mut out, entry);
    }
    out
}

#[test]
fn a_roster_holds_eight_members_and_refuses_nine() {
    let nine = members_of_width(9, 32, 1);
    let eight = nine[..8].to_vec();
    let authority = eight[0].clone();

    let accepted = roster(1, authority.clone(), eight.clone()).expect("eight members");
    assert_eq!(accepted.members.len(), 8);
    assert_eq!(
        roster(1, authority.clone(), nine.clone()).map(|_| ()),
        Err(Error::TooManyMembers)
    );

    // The raw builder reproduces the real encoding, so the refusals below
    // break exactly one thing.
    let encoded = accepted.encode().unwrap();
    assert_eq!(raw_roster(1, &authority, 8, &eight), encoded);
    assert_eq!(Roster::decode(&encoded), Ok(accepted));
    assert_eq!(
        Roster::decode(&raw_roster(1, &authority, 9, &nine)),
        Err(Error::TooManyMembers)
    );
}

#[test]
fn an_invitation_book_lets_a_seventh_member_invite_and_refuses_at_eight() {
    let members = members_of_width(8, 32, 1);
    let authority = members[0].clone();
    let invitation = |id: u8| {
        Invitation::new(
            InvitationId::new([id; 16]),
            group(),
            small("newcomer"),
            0,
            [0; DIGEST_LEN],
            POLICY_VERSION_V1,
            10,
        )
        .unwrap()
    };
    let mut book = InvitationBook::new(group());
    assert!(
        book.create(&authority, &authority, &members[..7], invitation(1), 0)
            .is_ok()
    );
    let mut refused = InvitationBook::new(group());
    assert_eq!(
        refused
            .create(&authority, &authority, &members[..8], invitation(1), 0)
            .map(|_| ()),
        Err(Error::TooManyMembers)
    );
}

/// Mirrors `LogicalSend::encode_intent`.
fn raw_intent(
    sender: &Member,
    sequence: u64,
    payload_len: usize,
    declared_recipients: u32,
    recipients: &[Member],
) -> Vec<u8> {
    fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }
    let mut out = b"Tacenta Group Logical Send v1".to_vec();
    lp(&mut out, group().as_bytes());
    out.extend_from_slice(&1u64.to_be_bytes());
    lp(&mut out, sender.identity());
    lp(&mut out, sender.device());
    out.extend_from_slice(&sequence.to_be_bytes());
    lp(&mut out, &[9; DIGEST_LEN]);
    lp(&mut out, &vec![b'p'; payload_len]);
    out.extend_from_slice(&declared_recipients.to_be_bytes());
    for recipient in recipients {
        lp(&mut out, recipient.identity());
        lp(&mut out, recipient.device());
    }
    out
}

#[test]
fn a_logical_intent_names_at_most_eight_recipients() {
    let members = members_of_width(9, 32, 1);
    let sender = members[0].clone();
    let eight = &members[..8];
    let send = LogicalSend::new(
        &roster(1, sender.clone(), eight.to_vec()).unwrap(),
        [9; DIGEST_LEN],
        sender.clone(),
        0,
        eight.to_vec(),
        vec![b'p'; 4],
    )
    .expect("eight recipients");
    assert_eq!(send.recipients().len(), 8);
    let encoded = send.encode_intent().unwrap();
    assert_eq!(raw_intent(&sender, 0, 4, 8, eight), encoded);
    assert_eq!(LogicalSend::decode_intent(&encoded), Ok(send));
    assert_eq!(
        LogicalSend::decode_intent(&raw_intent(&sender, 0, 4, 9, &members)),
        Err(Error::TooManyMembers)
    );
    assert_eq!(
        LogicalSend::decode_intent(&raw_intent(&sender, 0, 4, 0, &[])),
        Err(Error::EmptyRecipients)
    );
}

// ---------------------------------------------------------------------------
// 1,024 payload bytes
// ---------------------------------------------------------------------------

#[test]
fn an_application_payload_may_be_1024_bytes_and_not_1025() {
    let context = |len: usize| {
        ApplicationContext::new(
            group(),
            1,
            [7; DIGEST_LEN],
            small("alice"),
            small("bob"),
            0,
            vec![0; len],
        )
    };
    let accepted = context(1_024).expect("1,024 bytes");
    assert_eq!(
        ApplicationContext::decode(&accepted.encode().unwrap()),
        Ok(accepted)
    );
    assert_eq!(context(1_025), Err(Error::PayloadTooLarge));
    assert!(context(0).is_ok());
}

#[test]
fn a_logical_send_and_its_recovered_intent_carry_at_most_1024_payload_bytes() {
    let alice = small("alice");
    let bob = small("bob");
    let members = vec![alice.clone(), bob.clone()];
    let roster = roster(1, alice.clone(), members).unwrap();
    let send = |len: usize| {
        LogicalSend::new(
            &roster,
            [9; DIGEST_LEN],
            alice.clone(),
            0,
            vec![bob.clone()],
            vec![b'p'; len],
        )
    };
    assert!(send(1_024).is_ok());
    assert_eq!(send(1_025).map(|_| ()), Err(Error::PayloadTooLarge));

    let recipients = [bob.clone()];
    assert!(LogicalSend::decode_intent(&raw_intent(&alice, 0, 1_024, 1, &recipients)).is_ok());
    assert_eq!(
        LogicalSend::decode_intent(&raw_intent(&alice, 0, 1_025, 1, &recipients)),
        Err(Error::PayloadTooLarge)
    );
}

// ---------------------------------------------------------------------------
// 256 identity bytes and 64 device bytes
// ---------------------------------------------------------------------------

#[test]
fn an_identity_may_be_256_bytes_and_not_257() {
    let at_cap = wide(1, 256, 1);
    assert!(roster(1, at_cap.clone(), vec![at_cap.clone()]).is_ok());
    let over = wide(1, 257, 1);
    assert_eq!(
        roster(1, over.clone(), vec![over.clone()]).map(|_| ()),
        Err(Error::IdentityTooLarge)
    );
    // The decoder refuses it too, before the roster is assembled.
    assert_eq!(
        Roster::decode(&raw_roster(1, &over, 1, std::slice::from_ref(&over))),
        Err(Error::IdentityTooLarge)
    );
    let recipient = small("bob");
    assert!(
        ApplicationContext::new(
            group(),
            1,
            [7; DIGEST_LEN],
            at_cap,
            recipient.clone(),
            0,
            vec![]
        )
        .is_ok()
    );
    assert_eq!(
        ApplicationContext::new(group(), 1, [7; DIGEST_LEN], over, recipient, 0, vec![])
            .map(|_| ()),
        Err(Error::IdentityTooLarge)
    );
}

#[test]
fn a_device_may_be_64_bytes_and_not_65() {
    let at_cap = wide(1, 8, 64);
    assert!(roster(1, at_cap.clone(), vec![at_cap.clone()]).is_ok());
    let over = wide(1, 8, 65);
    assert_eq!(
        roster(1, over.clone(), vec![over.clone()]).map(|_| ()),
        Err(Error::DeviceTooLarge)
    );
    assert_eq!(
        Roster::decode(&raw_roster(1, &over, 1, std::slice::from_ref(&over))),
        Err(Error::DeviceTooLarge)
    );
    assert!(
        Invitation::new(
            InvitationId::new([1; 16]),
            group(),
            at_cap,
            0,
            [0; DIGEST_LEN],
            POLICY_VERSION_V1,
            10,
        )
        .is_ok()
    );
    assert_eq!(
        Invitation::new(
            InvitationId::new([1; 16]),
            group(),
            over,
            0,
            [0; DIGEST_LEN],
            POLICY_VERSION_V1,
            10,
        )
        .map(|_| ()),
        Err(Error::DeviceTooLarge)
    );
}

// ---------------------------------------------------------------------------
// 4,096 roster bytes and 2,048 context bytes
// ---------------------------------------------------------------------------

#[test]
fn the_roster_size_bound_is_4096_and_the_largest_valid_roster_is_3048() {
    // Input larger than the bound is refused before it is parsed; an input at
    // the bound is parsed (and, being zeros, malformed).
    assert_eq!(Roster::decode(&vec![0; 4_096]), Err(Error::Malformed));
    assert_eq!(Roster::decode(&vec![0; 4_097]), Err(Error::RosterTooLarge));
    assert_eq!(Roster::decode(&[]), Err(Error::Malformed));

    // Eight maximal bindings: 23 + 20 + 8 + 36 + 328 (authority) + 4 + 1 + 4
    // + 8 * 328 = 3,048 bytes, so no valid roster reaches the bound.
    let members = members_of_width(8, 256, 64);
    let largest = roster(1, members[0].clone(), members).expect("largest roster");
    let encoded = largest.encode().unwrap();
    assert_eq!(encoded.len(), 3_048);
    assert_eq!(Roster::decode(&encoded), Ok(largest));
}

#[test]
fn the_context_size_bound_is_2048_and_the_largest_valid_context_is_1784() {
    assert_eq!(
        ApplicationContext::decode(&vec![0; 2_048]),
        Err(Error::Malformed)
    );
    assert_eq!(
        ApplicationContext::decode(&vec![0; 2_049]),
        Err(Error::ContextTooLarge)
    );
    // 28 + 20 + 8 + 36 + 328 + 328 + 8 + 4 + 1,024 = 1,784 bytes.
    let context = ApplicationContext::new(
        group(),
        1,
        [7; DIGEST_LEN],
        wide(1, 256, 64),
        wide(2, 256, 64),
        u64::MAX,
        vec![0; 1_024],
    )
    .expect("largest context");
    let encoded = context.encode().unwrap();
    assert_eq!(encoded.len(), 1_784);
    assert_eq!(ApplicationContext::decode(&encoded), Ok(context));
}

// ---------------------------------------------------------------------------
// Eight live logical sends and three attempts
// ---------------------------------------------------------------------------

fn outbox_send(sequence: u64) -> LogicalSend {
    let alice = small("alice");
    let bob = small("bob");
    let roster = roster(1, alice.clone(), vec![alice.clone(), bob.clone()]).unwrap();
    LogicalSend::new(
        &roster,
        [9; DIGEST_LEN],
        alice,
        sequence,
        vec![bob],
        b"hello".to_vec(),
    )
    .unwrap()
}

#[test]
fn an_outbox_holds_eight_live_sends_and_refuses_a_ninth() {
    let mut outbox = GroupOutbox::new(group());
    for sequence in 0..8 {
        assert_eq!(
            outbox.record(outbox_send(sequence)),
            Ok(OutboxDisposition::Inserted),
            "send {sequence}"
        );
    }
    assert_eq!(outbox.record(outbox_send(8)), Err(Error::OutboxFull));
    assert_eq!(outbox.sends().len(), 8);
}

#[test]
fn a_terminal_send_frees_its_live_slot() {
    let bob = small("bob");
    let mut outbox = GroupOutbox::new(group());
    for sequence in 0..8 {
        outbox.record(outbox_send(sequence)).unwrap();
    }
    // Finish the first send: prepared, handed off, relay accepted.
    let first = outbox.sends()[0].id.clone();
    let send = outbox.send_mut(&first).unwrap();
    send.record_prepared(&bob, [1; DIGEST_LEN], vec![1])
        .unwrap();
    send.reserve_handoff(&bob).unwrap();
    send.record_relay_accepted(&bob).unwrap();
    assert_eq!(
        outbox.record(outbox_send(8)),
        Ok(OutboxDisposition::Inserted)
    );
    assert_eq!(outbox.record(outbox_send(9)), Err(Error::OutboxFull));
}

#[test]
fn a_recipient_reserves_three_attempts_and_a_fourth_is_refused() {
    let bob = small("bob");
    let mut send = outbox_send(0);
    send.record_prepared(&bob, [1; DIGEST_LEN], vec![1, 2, 3])
        .unwrap();
    for (attempt, disposition) in [
        (1, RecipientDisposition::HandedOff),
        (2, RecipientDisposition::HandedOff),
        (3, RecipientDisposition::ExhaustedUnknown),
    ] {
        let progress = send.reserve_handoff(&bob).unwrap();
        assert_eq!(progress.attempts_reserved, attempt);
        assert_eq!(progress.disposition, disposition);
    }
    assert_eq!(
        send.reserve_handoff(&bob).map(|_| ()),
        Err(Error::RetryExhausted)
    );
    assert_eq!(send.recipients()[0].attempts_reserved, 3);
}

// ---------------------------------------------------------------------------
// 32 invitation records
// ---------------------------------------------------------------------------

fn invitation_for(index: u8) -> Invitation {
    Invitation::new(
        InvitationId::new([index; 16]),
        group(),
        Member::new(vec![b't', index], vec![1]),
        0,
        [0; DIGEST_LEN],
        POLICY_VERSION_V1,
        10,
    )
    .unwrap()
}

#[test]
fn an_invitation_book_holds_32_records_and_refuses_a_33rd() {
    let authority = small("alice");
    let mut book = InvitationBook::new(group());
    for index in 0..32u8 {
        book.create(
            &authority,
            &authority,
            std::slice::from_ref(&authority),
            invitation_for(index),
            0,
        )
        .unwrap_or_else(|error| panic!("record {index}: {error}"));
    }
    assert_eq!(book.records().len(), 32);
    assert_eq!(
        book.create(
            &authority,
            &authority,
            std::slice::from_ref(&authority),
            invitation_for(32),
            0,
        )
        .map(|_| ()),
        Err(Error::OutboxFull)
    );
    // An exact retry of a stored record is not a new record.
    assert!(
        book.create(
            &authority,
            &authority,
            std::slice::from_ref(&authority),
            invitation_for(31),
            0,
        )
        .is_ok()
    );

    // The checkpoint codec has the same bound. A 33rd record is appended to
    // an otherwise valid state, in ascending ID order.
    let state = book.encode_state().unwrap();
    assert_eq!(
        InvitationBook::decode_state(&state, group())
            .unwrap()
            .records()
            .len(),
        32
    );
    let header = b"Tacenta Group Invitation Book State v1".len() + GROUP_ID_LEN;
    let record_len = 16 + 2 + 2 + 2 + 1 + 8 + DIGEST_LEN + 4 + 8 + 1;
    assert_eq!(state.len(), header + 1 + 32 * record_len);
    let mut thirty_three = state.clone();
    thirty_three[header] = 33;
    let mut extra = state[state.len() - record_len..].to_vec();
    extra[..16].copy_from_slice(&[32; 16]);
    extra[19] = 32; // keep the target identity distinct: b't' then the record index
    thirty_three.extend_from_slice(&extra);
    assert_eq!(
        InvitationBook::decode_state(&thirty_three, group()).map(|_| ()),
        Err(Error::Malformed)
    );
}

// ---------------------------------------------------------------------------
// Receiver bounds: 64-sequence window, two future revisions, four deferred,
// 512 accepted entries, 256 KiB state
// ---------------------------------------------------------------------------

const ROSTER_DIGEST: [u8; DIGEST_LEN] = [9; DIGEST_LEN];

fn context_from(
    sender: &Member,
    recipient: &Member,
    revision: u64,
    sequence: u64,
) -> ApplicationContext {
    ApplicationContext::new(
        group(),
        revision,
        ROSTER_DIGEST,
        sender.clone(),
        recipient.clone(),
        sequence,
        b"x".to_vec(),
    )
    .unwrap()
}

fn two_party_receiver(revision: u64) -> (GroupReceiver, Member, Member) {
    let alice = small("alice");
    let bob = small("bob");
    let receiver = GroupReceiver::new(
        roster(revision, alice.clone(), vec![alice.clone(), bob.clone()]).unwrap(),
        ROSTER_DIGEST,
        bob.clone(),
    );
    (receiver, alice, bob)
}

#[test]
fn the_dedup_window_is_64_sequences() {
    let (mut receiver, alice, bob) = two_party_receiver(2);
    assert_eq!(
        receiver.receive(&context_from(&alice, &bob, 2, 100), &alice, [1; DIGEST_LEN]),
        ReceiveDisposition::Accepted { event_id: 0 }
    );
    // 36 + 64 = 100 is at the edge and expired; 37 + 64 = 101 is still inside.
    assert_eq!(
        receiver.receive(&context_from(&alice, &bob, 2, 36), &alice, [1; DIGEST_LEN]),
        ReceiveDisposition::Rejected(ReceiveRefusal::SequenceExpired)
    );
    assert_eq!(
        receiver.receive(&context_from(&alice, &bob, 2, 37), &alice, [1; DIGEST_LEN]),
        ReceiveDisposition::Accepted { event_id: 1 }
    );
}

#[test]
fn the_future_window_is_two_revisions_and_the_queue_holds_four() {
    let (mut receiver, alice, bob) = two_party_receiver(2);
    // Revision 2 is current: 4 is the last revision that defers, 5 is refused.
    assert_eq!(
        receiver.receive(&context_from(&alice, &bob, 4, 0), &alice, [1; DIGEST_LEN]),
        ReceiveDisposition::Deferred
    );
    assert_eq!(
        receiver.receive(&context_from(&alice, &bob, 5, 0), &alice, [1; DIGEST_LEN]),
        ReceiveDisposition::Rejected(ReceiveRefusal::FutureOutOfRange)
    );
    // Four items fill the queue, a fifth distinct one is refused, and an exact
    // repeat of a queued one still reuses its slot.
    for (revision, sequence) in [(3, 0), (3, 1), (4, 1)] {
        assert_eq!(
            receiver.receive(
                &context_from(&alice, &bob, revision, sequence),
                &alice,
                [1; DIGEST_LEN]
            ),
            ReceiveDisposition::Deferred,
            "({revision}, {sequence})"
        );
    }
    assert_eq!(
        receiver.receive(&context_from(&alice, &bob, 4, 2), &alice, [1; DIGEST_LEN]),
        ReceiveDisposition::Rejected(ReceiveRefusal::DeferredFull)
    );
    assert_eq!(
        receiver.receive(&context_from(&alice, &bob, 3, 0), &alice, [1; DIGEST_LEN]),
        ReceiveDisposition::Deferred
    );
}

fn commit_roster(_: &[u8]) -> [u8; DIGEST_LEN] {
    ROSTER_DIGEST
}

fn commit_payload(_: &[u8]) -> [u8; DIGEST_LEN] {
    [1; DIGEST_LEN]
}

/// Builds a receiver state by hand: `accepted` entries for one sender at
/// sequences `0..accepted`, then the given deferred contexts. It mirrors
/// `GroupReceiver::encode_state`, and the first test below checks that.
struct Crafted<'a> {
    roster_bytes: &'a [u8],
    local: &'a Member,
    sender: &'a Member,
    revision: u64,
}

impl Crafted<'_> {
    fn state(
        &self,
        accepted: u32,
        declared_accepted: u32,
        deferred: &[ApplicationContext],
        declared_deferred: u32,
    ) -> Vec<u8> {
        fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        fn member(out: &mut Vec<u8>, member: &Member) {
            lp(out, member.identity());
            lp(out, member.device());
        }
        let mut out = b"Tacenta Group Receiver State v1".to_vec();
        lp(&mut out, self.roster_bytes);
        out.extend_from_slice(&ROSTER_DIGEST);
        member(&mut out, self.local);
        out.extend_from_slice(&u64::from(accepted).to_be_bytes());
        out.extend_from_slice(&declared_accepted.to_be_bytes());
        for sequence in 0..accepted {
            out.extend_from_slice(&self.revision.to_be_bytes());
            member(&mut out, self.sender);
            out.extend_from_slice(&u64::from(sequence).to_be_bytes());
            out.extend_from_slice(&[1; DIGEST_LEN]);
            out.extend_from_slice(&u64::from(sequence).to_be_bytes());
        }
        out.extend_from_slice(&declared_deferred.to_be_bytes());
        for context in deferred {
            lp(&mut out, &context.encode().unwrap());
            out.extend_from_slice(&[1; DIGEST_LEN]);
        }
        out
    }
}

fn decode(bytes: &[u8]) -> Result<GroupReceiver, Error> {
    GroupReceiver::decode_state(bytes, commit_roster, commit_payload)
}

#[test]
fn receiver_state_holds_512_accepted_entries_and_four_deferred_contexts() {
    let (mut real, alice, bob) = two_party_receiver(2);
    let roster_bytes = roster(2, alice.clone(), vec![alice.clone(), bob.clone()])
        .unwrap()
        .encode()
        .unwrap();
    for sequence in 0..3u64 {
        real.receive(
            &context_from(&alice, &bob, 2, sequence),
            &alice,
            [1; DIGEST_LEN],
        );
    }
    // The hand-built encoder agrees with the real one, so it can be used to
    // reach counts the receiver itself never produces.
    let crafted = Crafted {
        roster_bytes: &roster_bytes,
        local: &bob,
        sender: &alice,
        revision: 2,
    };
    assert_eq!(crafted.state(3, 3, &[], 0), real.encode_state().unwrap());

    let deferred = |count: usize| -> Vec<ApplicationContext> {
        [(3, 0), (3, 1), (4, 0), (4, 1), (4, 2)][..count]
            .iter()
            .map(|&(revision, sequence)| context_from(&alice, &bob, revision, sequence))
            .collect()
    };
    // 512 = 8 members x 64-sequence window; 513 is refused.
    assert!(decode(&crafted.state(512, 512, &[], 0)).is_ok());
    assert_eq!(
        decode(&crafted.state(513, 513, &[], 0)).map(|_| ()),
        Err(Error::Malformed)
    );
    // Four deferred contexts are accepted, five are refused.
    let four = deferred(4);
    assert!(decode(&crafted.state(0, 0, &four, 4)).is_ok());
    let five = deferred(5);
    assert_eq!(
        decode(&crafted.state(0, 0, &five, 5)).map(|_| ()),
        Err(Error::Malformed)
    );
}

#[test]
fn the_largest_receiver_state_is_207347_bytes_and_round_trips() {
    // Eight maximal bindings, all eight senders at a full 64-sequence window,
    // and four deferred maximal contexts.
    let members = members_of_width(8, 256, 64);
    let local = members[0].clone();
    let accepted_roster = roster(2, local.clone(), members.clone()).unwrap();
    let mut receiver = GroupReceiver::new(accepted_roster, ROSTER_DIGEST, local.clone());
    let mut event = 0;
    for sender in &members {
        for sequence in 0..64 {
            let mut context = context_from(sender, &local, 2, sequence);
            context.payload = vec![0; 1_024];
            assert_eq!(
                receiver.receive(&context, sender, [1; DIGEST_LEN]),
                ReceiveDisposition::Accepted { event_id: event }
            );
            event += 1;
        }
    }
    for (revision, sequence) in [(3, 0), (3, 1), (4, 0), (4, 1)] {
        let mut context = context_from(&members[1], &local, revision, sequence);
        context.payload = vec![0; 1_024];
        assert_eq!(
            receiver.receive(&context, &members[1], [1; DIGEST_LEN]),
            ReceiveDisposition::Deferred
        );
    }
    let encoded = receiver.encode_state().unwrap();
    // 31 + 4 + 3,048 + 32 + 328 + 8 + 4 + 512 * 384 + 4 + 4 * (4 + 1,784 + 32).
    assert_eq!(encoded.len(), 207_347);
    assert_eq!(decode(&encoded), Ok(receiver));
}

// ---------------------------------------------------------------------------
// The 8 KiB group payload bound
// ---------------------------------------------------------------------------

#[test]
fn the_largest_group_payload_is_3526_bytes_and_the_bound_is_8192() {
    // The bound is above every valid payload, so it only refuses an oversized
    // input before parsing. The largest valid payload carries an invitation
    // bootstrap over a maximal roster: 24 + 1 + 4 + 3,497 = 3,526 bytes.
    let members = members_of_width(8, 256, 64);
    let authority = members[0].clone();
    let big_source = roster(1, authority, members).unwrap();
    let invitation = Invitation::new(
        InvitationId::new([1; 16]),
        group(),
        wide(9, 256, 64),
        1,
        [3; DIGEST_LEN],
        POLICY_VERSION_V1,
        10,
    )
    .unwrap();
    let payload = GroupPayload::InvitationBootstrap(
        InvitationBootstrap::new(invitation, big_source).unwrap(),
    );
    let encoded = payload.encode().unwrap();
    assert_eq!(encoded.len(), 3_526);
    assert_eq!(GroupPayload::decode(&encoded), Ok(payload));

    let mut at_bound = encoded.clone();
    at_bound.resize(8_192, 0);
    assert_eq!(GroupPayload::decode(&at_bound), Err(Error::Malformed));
    let mut over_bound = encoded;
    over_bound.resize(8_193, 0);
    assert_eq!(GroupPayload::decode(&over_bound), Err(Error::Malformed));
}
