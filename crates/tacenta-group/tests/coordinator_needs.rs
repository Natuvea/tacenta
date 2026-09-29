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
