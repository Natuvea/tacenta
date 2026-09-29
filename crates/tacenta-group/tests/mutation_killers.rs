//! Killers added after the group-crate mutation rerun that followed the
//! CR-06/CR-12 fixes (`tooling/group-mutation`). Each names the mutant it
//! kills; the rerun's report lists the survivors that stay, with reasons.

use tacenta_group::*;

fn group() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}

fn named(name: &str) -> Member {
    Member::new(name.as_bytes().to_vec(), vec![1])
}

fn roster(revision: u64, closed: bool, members: &[&str]) -> Roster {
    Roster::new(
        group(),
        revision,
        [0; DIGEST_LEN],
        named("alice"),
        POLICY_VERSION_V1,
        closed,
        members.iter().map(|name| named(name)).collect(),
    )
    .unwrap()
}

const DIGEST: [u8; DIGEST_LEN] = [9; DIGEST_LEN];

fn context(sender: &str, recipient: &str, revision: u64, sequence: u64) -> ApplicationContext {
    ApplicationContext::new(
        group(),
        revision,
        DIGEST,
        named(sender),
        named(recipient),
        sequence,
        b"x".to_vec(),
    )
    .unwrap()
}

fn restore(bytes: &[u8]) -> Result<GroupReceiver, Error> {
    GroupReceiver::decode_state(bytes, |_| DIGEST, |_| [1; DIGEST_LEN])
}

#[test]
fn gc_r03_a_sender_outside_the_roster_is_refused_as_not_active() {
    let mut receiver =
        GroupReceiver::new(roster(2, false, &["alice", "bob"]), DIGEST, named("bob"));
    assert_eq!(
        receiver.receive(
            &context("carol", "bob", 2, 0),
            &named("carol"),
            [1; DIGEST_LEN]
        ),
        ReceiveDisposition::Rejected(ReceiveRefusal::NotActive)
    );
    // The same context from a member is accepted, so the refusal is the sender.
    assert_eq!(
        receiver.receive(
            &context("alice", "bob", 2, 0),
            &named("alice"),
            [1; DIGEST_LEN]
        ),
        ReceiveDisposition::Accepted { event_id: 0 }
    );
}

#[test]
fn gc_v06_a_successor_with_another_policy_version_is_refused() {
    let genesis = Roster::new(
        group(),
        0,
        [0; DIGEST_LEN],
        named("alice"),
        POLICY_VERSION_V1,
        false,
        vec![named("alice")],
    )
    .unwrap();
    let mut view = RosterView::accept_genesis(&named("alice"), genesis, [1; DIGEST_LEN]).unwrap();
    // `Roster::new` refuses another policy, but the fields are public, so a
    // caller can still hand the view such a value.
    let mut successor = Roster::new(
        group(),
        1,
        [1; DIGEST_LEN],
        named("alice"),
        POLICY_VERSION_V1,
        false,
        vec![named("alice"), named("bob")],
    )
    .unwrap();
    successor.policy_version = 2;
    assert_eq!(
        view.accept_successor(&named("alice"), successor, [2; DIGEST_LEN]),
        RosterDisposition::Rejected(RosterRefusal::PolicyChange)
    );
    assert_eq!(view.roster().revision, 0);
}

#[test]
fn gc_s15_a_cancelled_but_prepared_recipient_cannot_reserve_a_handoff() {
    let alice = named("alice");
    let bob = named("bob");
    let roster = roster(1, false, &["alice", "bob"]);
    let mut send = LogicalSend::new(
        &roster,
        [5; DIGEST_LEN],
        alice,
        0,
        vec![bob.clone()],
        b"hello".to_vec(),
    )
    .unwrap();
    send.record_prepared(&bob, [1; DIGEST_LEN], vec![1, 2, 3])
        .unwrap();
    assert_eq!(
        send.cancel_for_roster_change(&bob).unwrap().disposition,
        RecipientDisposition::Cancelled
    );
    assert_eq!(
        send.reserve_handoff(&bob).map(|_| ()),
        Err(Error::WrongDisposition)
    );
    let progress = &send.recipients()[0];
    assert_eq!(progress.disposition, RecipientDisposition::Cancelled);
    assert_eq!(progress.attempts_reserved, 0);
}

/// Offset of the embedded roster's `closed` byte in an encoded receiver
/// state whose authority is `alice` (identity and device as `named` builds).
fn closed_byte_offset() -> usize {
    let authority = named("alice");
    b"Tacenta Group Receiver State v1".len()
        + 4
        + b"Tacenta Group Roster v1".len()
        + 4
        + GROUP_ID_LEN
        + 8
        + 4
        + DIGEST_LEN
        + 4
        + authority.identity().len()
        + 4
        + authority.device().len()
        + 4
}

#[test]
fn gc_n21_a_closed_receiver_state_with_a_deferred_context_is_refused() {
    let mut live = GroupReceiver::new(roster(2, false, &["alice", "bob"]), DIGEST, named("bob"));
    assert_eq!(
        live.receive(
            &context("alice", "bob", 3, 0),
            &named("alice"),
            [1; DIGEST_LEN]
        ),
        ReceiveDisposition::Deferred
    );
    let mut bytes = live.encode_state().unwrap();
    assert_eq!(bytes[closed_byte_offset()], 0);
    assert!(restore(&bytes).is_ok(), "the untouched state is valid");
    bytes[closed_byte_offset()] = 1;
    assert_eq!(restore(&bytes).map(|_| ()), Err(Error::NonCanonical));
}

#[test]
fn gc_n23_a_receiver_state_for_a_binding_outside_the_roster_must_be_empty() {
    let mut live = GroupReceiver::new(roster(2, false, &["alice", "bob"]), DIGEST, named("bob"));
    assert!(matches!(
        live.receive(
            &context("alice", "bob", 2, 0),
            &named("alice"),
            [1; DIGEST_LEN]
        ),
        ReceiveDisposition::Accepted { .. }
    ));
    let mut bytes = live.encode_state().unwrap();
    // Rename the local binding "bob" to "bo2" (same length), which is not in
    // the roster, while the accepted entry stays.
    let roster_len = u32::from_be_bytes(bytes[31..35].try_into().unwrap()) as usize;
    let identity_at = 31 + 4 + roster_len + DIGEST_LEN + 4;
    assert_eq!(&bytes[identity_at..identity_at + 3], b"bob");
    bytes[identity_at + 2] = b'2';
    assert_eq!(restore(&bytes).map(|_| ()), Err(Error::NonCanonical));
}

// ---------------------------------------------------------------------------
// Guards that back each other up. Each of these survives a single mutation
// (a second check returns the same error) and is killed by the double (D10,
// D11, D12 in tooling/group-mutation/mutants.py).
// ---------------------------------------------------------------------------

#[test]
fn gc_l10_a_roster_that_lists_a_member_twice_is_refused() {
    let alice = named("alice");
    assert_eq!(
        Roster::new(
            group(),
            1,
            [0; DIGEST_LEN],
            alice.clone(),
            POLICY_VERSION_V1,
            false,
            vec![alice.clone(), alice],
        )
        .map(|_| ()),
        Err(Error::NonCanonical)
    );
}

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
/// ciphertext and a tag-specific suffix (the same layout `send.rs` recovers).
fn record(tag: &[u8; 4], context: &ApplicationContext, suffix: &[u8]) -> Vec<u8> {
    let context = context.encode().unwrap();
    let mut out = tag.to_vec();
    lp(&mut out, &context);
    out.extend_from_slice(&commit(&context));
    lp(&mut out, b"ciphertext");
    out.extend_from_slice(suffix);
    out
}

fn intent_record(send: &LogicalSend) -> Vec<u8> {
    let mut out = b"TCGI".to_vec();
    lp(&mut out, &send.encode_intent().unwrap());
    out
}

fn one_recipient_send() -> (LogicalSend, ApplicationContext) {
    let roster = roster(1, false, &["alice", "bob"]);
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

#[test]
fn gc_s11_recovery_refuses_a_handoff_record_that_skips_an_attempt() {
    let (send, context) = one_recipient_send();
    // The first handoff record must carry attempt 1; a record claiming 2 is a
    // gap in the durable attempt count.
    let entries = vec![
        intent_record(&send),
        record(b"TCGP", &context, &[]),
        record(b"TCGH", &context, &[2, 0]),
    ];
    assert_eq!(
        GroupOutbox::recover_from_transcript(group(), &entries, commit).map(|_| ()),
        Err(Error::Malformed)
    );
    let entries = vec![
        intent_record(&send),
        record(b"TCGP", &context, &[]),
        record(b"TCGH", &context, &[1, 0]),
    ];
    assert!(GroupOutbox::recover_from_transcript(group(), &entries, commit).is_ok());
}

#[test]
fn gc_s12_recovery_refuses_relay_acceptance_without_a_handoff() {
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
    let entries = vec![
        intent_record(&send),
        record(b"TCGP", &context, &[]),
        record(b"TCGH", &context, &[1, 0]),
        record(b"TCGA", &context, &[]),
    ];
    let recovered = GroupOutbox::recover_from_transcript(group(), &entries, commit).unwrap();
    assert_eq!(
        recovered.sends()[0].recipients()[0].disposition,
        RecipientDisposition::RelayAccepted
    );
}
