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
