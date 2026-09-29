//! Tests for the five group crate changes the client's coordinator needed
//! (decision 0135). Each test fails on the code before its change and passes
//! after it; the git history of this file and of `src/` shows both states. They
//! use only the public API of `tacenta-group`.

use tacenta_group::*;

fn group() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}

fn named(name: &str) -> Member {
    Member::new(name.as_bytes().to_vec(), vec![1])
}

fn roster_at(revision: u64, names: &[&str]) -> Roster {
    let mut members: Vec<Member> = names.iter().map(|name| named(name)).collect();
    members.sort_by(|left, right| {
        left.identity()
            .cmp(right.identity())
            .then_with(|| left.device().cmp(right.device()))
    });
    Roster::new(
        group(),
        revision,
        [0; DIGEST_LEN],
        named(names[0]),
        POLICY_VERSION_V1,
        false,
        members,
    )
    .unwrap()
}

/// A stand-in for the core's payload commitment: the tests only need the
/// same function on both sides of a recovery.
fn commit(bytes: &[u8]) -> [u8; DIGEST_LEN] {
    let mut digest = [0u8; DIGEST_LEN];
    for (index, byte) in bytes.iter().enumerate() {
        digest[index % DIGEST_LEN] ^= byte;
    }
    digest
}

fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// A transcript record: tag, the recipient's context, its commitment, the
/// ciphertext and a tag-specific suffix (the layout `send.rs` recovers).
fn record_with(
    tag: &[u8; 4],
    context: &ApplicationContext,
    ciphertext: &[u8],
    suffix: &[u8],
) -> Vec<u8> {
    let context = context.encode().unwrap();
    let mut out = tag.to_vec();
    lp(&mut out, &context);
    out.extend_from_slice(&commit(&context));
    lp(&mut out, ciphertext);
    out.extend_from_slice(suffix);
    out
}

fn record(tag: &[u8; 4], context: &ApplicationContext, suffix: &[u8]) -> Vec<u8> {
    record_with(tag, context, b"ciphertext", suffix)
}

fn intent_record(send: &LogicalSend) -> Vec<u8> {
    let mut out = b"TCGI".to_vec();
    lp(&mut out, &send.encode_intent().unwrap());
    out
}

fn one_recipient_send() -> (LogicalSend, ApplicationContext) {
    let roster = roster_at(1, &["alice", "bob"]);
    let send = LogicalSend::new(
        &roster,
        [5; DIGEST_LEN],
        named("alice"),
        0,
        vec![named("bob")],
        b"hello".to_vec(),
    )
    .unwrap();
    let context = send.application_context(&named("bob")).unwrap();
    (send, context)
}

// ---------------------------------------------------------------------------
// 1. The final attempt can be recorded as accepted (decision 0135, item 1)
// ---------------------------------------------------------------------------

#[test]
fn the_final_attempt_can_be_recorded_as_relay_accepted() {
    let (mut send, _) = one_recipient_send();
    send.record_prepared(&named("bob"), [1; DIGEST_LEN], b"ciphertext".to_vec())
        .unwrap();
    // Two ordinary attempts, then the third reservation, which is the final
    // one and is exhausted before it is sent.
    send.reserve_handoff(&named("bob")).unwrap();
    send.reserve_handoff(&named("bob")).unwrap();
    let third = send.reserve_handoff(&named("bob")).unwrap();
    assert_eq!(third.attempts_reserved, 3);
    assert_eq!(third.disposition, RecipientDisposition::ExhaustedUnknown);

    // The relay accepted that third send.
    let accepted = send.record_relay_accepted(&named("bob")).unwrap();
    assert_eq!(accepted.disposition, RecipientDisposition::RelayAccepted);
    assert_eq!(accepted.attempts_reserved, 3);
    assert_eq!(accepted.ciphertext.as_deref(), Some(&b"ciphertext"[..]));
    assert!(send.is_terminal());
}

#[test]
fn acceptance_is_recorded_once_and_a_fourth_send_is_still_refused() {
    let (mut send, _) = one_recipient_send();
    send.record_prepared(&named("bob"), [1; DIGEST_LEN], b"ciphertext".to_vec())
        .unwrap();
    for _ in 0..3 {
        send.reserve_handoff(&named("bob")).unwrap();
    }
    // Without an acceptance a fourth reservation is refused and the recipient
    // stays exhausted; nothing is invented.
    assert_eq!(
        send.reserve_handoff(&named("bob")).map(|_| ()),
        Err(Error::RetryExhausted)
    );
    assert_eq!(
        send.recipients()[0].disposition,
        RecipientDisposition::ExhaustedUnknown
    );
    send.record_relay_accepted(&named("bob")).unwrap();
    // Once accepted, no second acceptance and no further reservation.
    assert_eq!(
        send.record_relay_accepted(&named("bob")).map(|_| ()),
        Err(Error::WrongDisposition)
    );
    assert_eq!(
        send.reserve_handoff(&named("bob")).map(|_| ()),
        Err(Error::WrongDisposition)
    );
}

#[test]
fn acceptance_still_needs_a_handoff() {
    let (mut send, _) = one_recipient_send();
    assert_eq!(
        send.record_relay_accepted(&named("bob")).map(|_| ()),
        Err(Error::WrongDisposition)
    );
    send.record_prepared(&named("bob"), [1; DIGEST_LEN], b"ciphertext".to_vec())
        .unwrap();
    assert_eq!(
        send.record_relay_accepted(&named("bob")).map(|_| ()),
        Err(Error::WrongDisposition)
    );
}

#[test]
fn recovery_replays_the_acceptance_of_the_final_attempt() {
    let (send, context) = one_recipient_send();
    let mut running = send.clone();
    running
        .record_prepared(
            &named("bob"),
            commit(&context.encode().unwrap()),
            b"ciphertext".to_vec(),
        )
        .unwrap();
    for _ in 0..3 {
        running.reserve_handoff(&named("bob")).unwrap();
    }
    running.record_relay_accepted(&named("bob")).unwrap();

    let entries = vec![
        intent_record(&send),
        record(b"TCGP", &context, &[]),
        record(b"TCGH", &context, &[1, 0]),
        record(b"TCGH", &context, &[2, 0]),
        record(b"TCGH", &context, &[3, 1]),
        record(b"TCGA", &context, &[]),
    ];
    let recovered = GroupOutbox::recover_from_transcript(group(), &entries, commit).unwrap();
    assert_eq!(recovered.sends(), &[running]);
    assert_eq!(
        recovered.sends()[0].recipients()[0].disposition,
        RecipientDisposition::RelayAccepted
    );
}

#[test]
fn recovery_of_an_exhausted_recipient_without_an_acceptance_stays_exhausted() {
    let (send, context) = one_recipient_send();
    let entries = vec![
        intent_record(&send),
        record(b"TCGP", &context, &[]),
        record(b"TCGH", &context, &[1, 0]),
        record(b"TCGH", &context, &[2, 0]),
        record(b"TCGH", &context, &[3, 1]),
    ];
    let recovered = GroupOutbox::recover_from_transcript(group(), &entries, commit).unwrap();
    assert_eq!(
        recovered.sends()[0].recipients()[0].disposition,
        RecipientDisposition::ExhaustedUnknown
    );
}

#[test]
fn recovery_refuses_an_acceptance_that_does_not_match_the_exhausted_handoff() {
    let (send, context) = one_recipient_send();
    let prefix = vec![
        intent_record(&send),
        record(b"TCGP", &context, &[]),
        record(b"TCGH", &context, &[1, 0]),
        record(b"TCGH", &context, &[2, 0]),
        record(b"TCGH", &context, &[3, 1]),
    ];
    // Different ciphertext from the one that was handed off.
    let mut other_bytes = prefix.clone();
    other_bytes.push(record_with(b"TCGA", &context, b"another", &[]));
    assert_eq!(
        GroupOutbox::recover_from_transcript(group(), &other_bytes, commit).map(|_| ()),
        Err(Error::Conflict)
    );
    // A second acceptance for the same recipient.
    let mut twice = prefix;
    twice.push(record(b"TCGA", &context, &[]));
    twice.push(record(b"TCGA", &context, &[]));
    assert_eq!(
        GroupOutbox::recover_from_transcript(group(), &twice, commit).map(|_| ()),
        Err(Error::WrongDisposition)
    );
}

#[test]
fn recovery_still_refuses_an_acceptance_with_no_handoff() {
    let (send, context) = one_recipient_send();
    let entries = vec![
        intent_record(&send),
        record(b"TCGP", &context, &[]),
        record(b"TCGA", &context, &[]),
    ];
    assert_eq!(
        GroupOutbox::recover_from_transcript(group(), &entries, commit).map(|_| ()),
        Err(Error::WrongDisposition)
    );
}

// ---------------------------------------------------------------------------
// 2. Recovery does not count sends a later cancellation made terminal
//    (decision 0135, item 2)
// ---------------------------------------------------------------------------

fn send_at(revision: u64, sequence: u64) -> LogicalSend {
    LogicalSend::new(
        &roster_at(revision, &["alice", "bob"]),
        [5; DIGEST_LEN],
        named("alice"),
        sequence,
        vec![named("bob")],
        b"hello".to_vec(),
    )
    .unwrap()
}

/// Records `count` sends at `revision` in a running outbox, and returns the
/// transcript records the client would have written for them.
fn record_sends(outbox: &mut GroupOutbox, entries: &mut Vec<Vec<u8>>, revision: u64, count: u64) {
    for sequence in 0..count {
        let send = send_at(revision, sequence);
        outbox.record(send.clone()).unwrap();
        entries.push(intent_record(&send));
    }
}

#[test]
fn recovery_does_not_count_sends_that_two_later_cancellations_made_terminal() {
    // Eight sends at revision 1 fill the live cap; a roster change to revision
    // 2 cancels them and eight more are recorded; a change to revision 3
    // cancels those. Sixteen sends crossed cancellations and none is live.
    let mut running = GroupOutbox::new(group());
    let mut entries = Vec::new();
    record_sends(&mut running, &mut entries, 1, 8);
    running.cancel_for_newer_roster(2);
    record_sends(&mut running, &mut entries, 2, 8);
    running.cancel_for_newer_roster(3);
    assert_eq!(running.sends().len(), 16);
    assert!(running.sends().iter().all(LogicalSend::is_terminal));

    // Without the cancellation the ninth send of the replay is over the cap.
    assert_eq!(
        GroupOutbox::recover_from_transcript(group(), &entries, commit).map(|_| ()),
        Err(Error::OutboxFull)
    );
    // With it, recovery equals the outbox that was running, including its
    // applied revision.
    let recovered =
        GroupOutbox::recover_from_transcript_at_revision(group(), &entries, Some(3), commit)
            .unwrap();
    assert_eq!(recovered, running);
}

#[test]
fn a_send_at_or_above_the_applied_revision_still_counts_toward_the_cap() {
    let mut running = GroupOutbox::new(group());
    let mut entries = Vec::new();
    record_sends(&mut running, &mut entries, 1, 8);
    running.cancel_for_newer_roster(2);
    record_sends(&mut running, &mut entries, 2, 8);
    // Eight live sends at the applied revision 2 recover, and equal the
    // running outbox: eight cancelled at revision 1, eight live at 2.
    let recovered =
        GroupOutbox::recover_from_transcript_at_revision(group(), &entries, Some(2), commit)
            .unwrap();
    assert_eq!(recovered, running);
    assert_eq!(
        recovered
            .sends()
            .iter()
            .filter(|send| !send.is_terminal())
            .count(),
        8
    );
    // A ninth live send at that revision is refused, as it would have been
    // when it was written.
    entries.push(intent_record(&send_at(2, 8)));
    assert_eq!(
        GroupOutbox::recover_from_transcript_at_revision(group(), &entries, Some(2), commit)
            .map(|_| ()),
        Err(Error::OutboxFull)
    );
}

#[test]
fn recovery_without_an_applied_revision_keeps_the_cap_and_the_old_meaning() {
    let mut entries = Vec::new();
    for sequence in 0..9 {
        entries.push(intent_record(&send_at(1, sequence)));
    }
    assert_eq!(
        GroupOutbox::recover_from_transcript(group(), &entries, commit).map(|_| ()),
        Err(Error::OutboxFull)
    );
    assert_eq!(
        GroupOutbox::recover_from_transcript_at_revision(group(), &entries, None, commit)
            .map(|_| ()),
        Err(Error::OutboxFull)
    );
    // Eight recover, and no revision is applied.
    entries.pop();
    let recovered = GroupOutbox::recover_from_transcript(group(), &entries, commit).unwrap();
    assert_eq!(recovered.sends().len(), 8);
    assert_eq!(
        recovered.next_sequence(1, &named("alice")).unwrap(),
        8,
        "sequence allocation follows the retained sends"
    );
}

#[test]
fn the_cancellation_is_applied_after_a_send_s_own_records() {
    // A send that reached `handed_off` before a roster change became
    // `cancelled_after_handoff`; its preparation and handoff records must
    // replay before the cancellation does.
    let send = send_at(1, 0);
    let context = send.application_context(&named("bob")).unwrap();
    let entries = vec![
        intent_record(&send),
        record(b"TCGP", &context, &[]),
        record(b"TCGH", &context, &[1, 0]),
    ];
    let mut running = GroupOutbox::new(group());
    running.record(send.clone()).unwrap();
    {
        let live = running.send_mut(&send.id).unwrap();
        live.record_prepared(
            &named("bob"),
            commit(&context.encode().unwrap()),
            b"ciphertext".to_vec(),
        )
        .unwrap();
        live.reserve_handoff(&named("bob")).unwrap();
    }
    running.cancel_for_newer_roster(2);
    let recovered =
        GroupOutbox::recover_from_transcript_at_revision(group(), &entries, Some(2), commit)
            .unwrap();
    assert_eq!(recovered, running);
    assert_eq!(
        recovered.sends()[0].recipients()[0].disposition,
        RecipientDisposition::CancelledAfterHandoff
    );
}

#[test]
fn a_recovered_outbox_refuses_a_send_below_the_applied_revision() {
    let entries = vec![intent_record(&send_at(1, 0))];
    let mut recovered =
        GroupOutbox::recover_from_transcript_at_revision(group(), &entries, Some(3), commit)
            .unwrap();
    assert_eq!(
        recovered.record(send_at(2, 0)).map(|_| ()),
        Err(Error::StaleRevision)
    );
    assert!(recovered.record(send_at(3, 0)).is_ok());
}

// ---------------------------------------------------------------------------
// 3. A roster view can start from a source roster at any revision
//    (decision 0135, item 3)
// ---------------------------------------------------------------------------

/// A chain of accepted rosters for alice, bob and carol, each committed to its
/// predecessor's digest, with the digests the integration would supply.
struct Chain {
    rosters: Vec<Roster>,
    digests: Vec<[u8; DIGEST_LEN]>,
}

fn chain() -> Chain {
    let mut rosters = Vec::new();
    let mut digests = Vec::new();
    let mut predecessor = [0; DIGEST_LEN];
    for (revision, names) in [
        (0u64, vec!["alice"]),
        (1, vec!["alice", "bob"]),
        (2, vec!["alice", "bob", "carol"]),
        (3, vec!["alice", "carol"]),
    ] {
        let mut members: Vec<Member> = names.iter().map(|name| named(name)).collect();
        members.sort_by(|left, right| {
            left.identity()
                .cmp(right.identity())
                .then_with(|| left.device().cmp(right.device()))
        });
        let roster = Roster::new(
            group(),
            revision,
            predecessor,
            named("alice"),
            POLICY_VERSION_V1,
            false,
            members,
        )
        .unwrap();
        let digest = commit(&roster.encode().unwrap());
        predecessor = digest;
        rosters.push(roster);
        digests.push(digest);
    }
    Chain { rosters, digests }
}

#[test]
fn a_view_starts_from_a_source_roster_at_a_later_revision() {
    let chain = chain();
    let view =
        RosterView::accept_source(&named("alice"), chain.rosters[2].clone(), chain.digests[2])
            .unwrap();
    assert_eq!(view.roster(), &chain.rosters[2]);
    assert_eq!(view.digest(), &chain.digests[2]);
    assert!(view.is_active(&named("carol")));

    // It observes the next successor from the authority, and no other.
    let mut next = view.clone();
    assert_eq!(
        next.accept_successor(&named("alice"), chain.rosters[3].clone(), chain.digests[3]),
        RosterDisposition::Accepted
    );
    assert_eq!(next.roster().revision, 3);
    let mut skipped = view.clone();
    assert_eq!(
        skipped.accept_successor(&named("bob"), chain.rosters[3].clone(), chain.digests[3]),
        RosterDisposition::Rejected(RosterRefusal::WrongAuthority)
    );
    // Its predecessor is the source, not an earlier roster it never saw.
    let mut behind = view;
    assert_eq!(
        behind.accept_successor(&named("alice"), chain.rosters[1].clone(), chain.digests[1]),
        RosterDisposition::Rejected(RosterRefusal::StaleRevision)
    );
}

#[test]
fn a_source_view_equals_the_view_a_replay_from_genesis_reaches() {
    let chain = chain();
    let mut replayed =
        RosterView::accept_genesis(&named("alice"), chain.rosters[0].clone(), chain.digests[0])
            .unwrap();
    for index in 1..=2 {
        assert_eq!(
            replayed.accept_successor(
                &named("alice"),
                chain.rosters[index].clone(),
                chain.digests[index]
            ),
            RosterDisposition::Accepted
        );
    }
    let from_source =
        RosterView::accept_source(&named("alice"), chain.rosters[2].clone(), chain.digests[2])
            .unwrap();
    assert_eq!(from_source, replayed);
}

#[test]
fn a_source_view_is_a_restorable_checkpoint() {
    let chain = chain();
    let view =
        RosterView::accept_source(&named("alice"), chain.rosters[2].clone(), chain.digests[2])
            .unwrap();
    let state = view.encode_state().unwrap();
    assert_eq!(
        RosterView::decode_state(&state, &named("alice"), commit),
        Ok(view)
    );
}

#[test]
fn a_source_at_revision_zero_follows_the_genesis_rules() {
    let chain = chain();
    let genesis = chain.rosters[0].clone();
    assert_eq!(
        RosterView::accept_source(&named("alice"), genesis.clone(), chain.digests[0]),
        RosterView::accept_genesis(&named("alice"), genesis.clone(), chain.digests[0])
    );
    assert_eq!(
        RosterView::accept_source(&named("bob"), genesis, chain.digests[0]),
        Err(RosterRefusal::WrongAuthority)
    );
}

#[test]
fn a_source_roster_is_refused_unless_it_names_the_authenticated_authority() {
    let chain = chain();
    // Authenticated as bob, but the roster's authority is alice.
    assert_eq!(
        RosterView::accept_source(&named("bob"), chain.rosters[2].clone(), chain.digests[2]),
        Err(RosterRefusal::WrongAuthority)
    );
    // Its authority is not one of its members.
    let without_authority = Roster::new(
        group(),
        2,
        [0; DIGEST_LEN],
        named("alice"),
        POLICY_VERSION_V1,
        false,
        vec![named("bob"), named("carol")],
    )
    .unwrap();
    assert_eq!(
        RosterView::accept_source(&named("alice"), without_authority, [1; DIGEST_LEN]),
        Err(RosterRefusal::MissingAuthorityMember)
    );
    // A closed roster admits nobody, so it cannot be a bootstrap source.
    let closed = Roster::new(
        group(),
        2,
        [0; DIGEST_LEN],
        named("alice"),
        POLICY_VERSION_V1,
        true,
        vec![named("alice"), named("bob")],
    )
    .unwrap();
    assert_eq!(
        RosterView::accept_source(&named("alice"), closed, [1; DIGEST_LEN]),
        Err(RosterRefusal::InvalidSource)
    );
}

// ---------------------------------------------------------------------------
// 4. The canonical member order is public (decision 0135, item 4)
// ---------------------------------------------------------------------------

fn mk(identity: &[u8], device: &[u8]) -> Member {
    Member::new(identity.to_vec(), device.to_vec())
}

#[test]
fn the_canonical_member_order_is_the_identity_then_device_pair() {
    use std::cmp::Ordering;
    // A proper prefix sorts first even when its device bytes are larger; the
    // order of the concatenations would say the opposite.
    assert_eq!(
        mk(b"a", &[0xff]).canonical_cmp(&mk(b"ab", &[])),
        Ordering::Less
    );
    assert_eq!(
        mk(b"ab", &[]).canonical_cmp(&mk(b"a", &[0xff])),
        Ordering::Greater
    );
    // Equal concatenations are two members, ordered by identity.
    assert_eq!(
        mk(b"a", b"bc").canonical_cmp(&mk(b"ab", b"c")),
        Ordering::Less
    );
    // The device only breaks a tie between equal identities.
    assert_eq!(
        mk(b"a", &[1]).canonical_cmp(&mk(b"a", &[2])),
        Ordering::Less
    );
    assert_eq!(
        mk(b"a", &[2]).canonical_cmp(&mk(b"a", &[2])),
        Ordering::Equal
    );
}

#[test]
fn sorting_by_the_public_order_yields_exactly_the_rosters_the_crate_accepts() {
    let mut members = vec![
        mk(b"ab", &[]),
        mk(b"a", &[0xff]),
        mk(b"b", &[1]),
        mk(b"ab", &[1]),
        mk(b"", &[7]),
    ];
    // A roster needs one member per identity: keep the first of each.
    members.sort_by(Member::canonical_cmp);
    members.dedup_by(|later, earlier| later.identity() == earlier.identity());
    let authority = members[0].clone();
    let build = |members: Vec<Member>| {
        Roster::new(
            group(),
            1,
            [0; DIGEST_LEN],
            authority.clone(),
            POLICY_VERSION_V1,
            false,
            members,
        )
        .map(|_| ())
    };
    assert_eq!(build(members.clone()), Ok(()));
    let mut reversed = members;
    reversed.reverse();
    assert_eq!(build(reversed), Err(Error::NonCanonical));
}
