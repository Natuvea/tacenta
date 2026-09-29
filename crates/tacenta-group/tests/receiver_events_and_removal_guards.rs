//! Guards of `GroupReceiver` (`crates/tacenta-group/src/receive.rs`) that the receive and delivery
//! changes of decisions 0142 and 0144 left unpinned: which refusal a removed member's receiver
//! reports, and how many event IDs a receiver says it has issued.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made. It uses only the public API of `tacenta-group`.
//!
//! - M141r (`receive.rs`, `GroupReceiver::receive`): the local-member `NotActive` check runs before
//!   the `WrongRecipient` check. Re-expresses M141 of the run against 97689a0, whose text no longer
//!   patches because the sender check moved after the future-revision check.
//! - R179 (`receive.rs`, `GroupReceiver::events_issued`): the count of retained accepted entries is
//!   reported instead of the next event ID.
//!
//! `R###` and `M###r` are ids of the single-change mutation run against 341e2b0.

use tacenta_group::*;

fn group() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}

fn named(name: &str) -> Member {
    Member::new(name.as_bytes().to_vec(), vec![1])
}

fn roster(revision: u64, names: &[&str]) -> Roster {
    let mut members: Vec<Member> = names.iter().map(|name| named(name)).collect();
    members.sort_by(Member::canonical_cmp);
    Roster::new(
        group(),
        revision,
        [0; DIGEST_LEN],
        named("alice"),
        POLICY_VERSION_V1,
        false,
        members,
    )
    .unwrap()
}

fn context(
    revision: u64,
    roster_digest: [u8; DIGEST_LEN],
    sender: &str,
    recipient: &str,
    sequence: u64,
) -> ApplicationContext {
    ApplicationContext::new(
        group(),
        revision,
        roster_digest,
        named(sender),
        named(recipient),
        sequence,
        b"hello".to_vec(),
    )
    .unwrap()
}

/// M141r: in `GroupReceiver::receive`, the local-member `NotActive` check runs before the
/// `WrongRecipient` check, so a context for another recipient that reaches the receiver of a
/// removed member is reported `NotActive` instead of `WrongRecipient`. The refusal is recorded
/// durably by the client (a code per refusal), so which of two applicable refusals is reported is
/// observable.
#[test]
fn m141r_wrong_recipient_is_reported_before_the_receiver_finds_itself_inactive() {
    // Bob was removed: the accepted roster lists Alice alone.
    let mut receiver = GroupReceiver::new(roster(1, &["alice"]), [7; DIGEST_LEN], named("bob"));
    assert_eq!(receiver.status(), ReceiverStatus::NotMember);
    let stray = context(1, [7; DIGEST_LEN], "alice", "carol", 0);
    assert_eq!(
        receiver.receive(&stray, &named("alice"), [1; DIGEST_LEN]),
        ReceiveDisposition::Rejected(ReceiveRefusal::WrongRecipient)
    );
    // A context for Bob himself is refused as not active.
    let to_bob = context(1, [7; DIGEST_LEN], "alice", "bob", 0);
    assert_eq!(
        receiver.receive(&to_bob, &named("alice"), [1; DIGEST_LEN]),
        ReceiveDisposition::Rejected(ReceiveRefusal::NotActive)
    );
}

/// R179: `GroupReceiver::events_issued` reports `self.accepted.len()` instead of `next_event_id`.
/// The accepted entries are cleared when a roster is installed and trimmed by the 64-sequence
/// window, so the number of IDs issued is larger than the number retained; the client's
/// `lost_events` count is computed from it (0144).
#[test]
fn r179_events_issued_counts_every_id_issued_not_the_entries_still_retained() {
    let digest_one = [9; DIGEST_LEN];
    let digest_two = [8; DIGEST_LEN];
    let mut receiver = GroupReceiver::new(roster(1, &["alice", "bob"]), digest_one, named("bob"));
    assert_eq!(receiver.events_issued(), 0);
    for sequence in 0..2 {
        let accepted = receiver.receive(
            &context(1, digest_one, "alice", "bob", sequence),
            &named("alice"),
            [sequence as u8 + 1; DIGEST_LEN],
        );
        assert_eq!(
            accepted,
            ReceiveDisposition::Accepted { event_id: sequence }
        );
    }
    assert_eq!(receiver.events_issued(), 2);

    // A roster install forgets the accepted entries of the earlier revision, not the IDs.
    receiver
        .install_accepted_roster(roster(2, &["alice", "bob"]), digest_two)
        .unwrap();
    assert_eq!(receiver.events_issued(), 2);
    let next = receiver.receive(
        &context(2, digest_two, "alice", "bob", 0),
        &named("alice"),
        [3; DIGEST_LEN],
    );
    assert_eq!(next, ReceiveDisposition::Accepted { event_id: 2 });
    assert_eq!(receiver.events_issued(), 3);

    // The count survives the state codec.
    let commit = |bytes: &[u8]| {
        let mut digest = [0u8; DIGEST_LEN];
        for (index, byte) in bytes.iter().enumerate() {
            digest[index % DIGEST_LEN] ^= byte;
        }
        digest
    };
    let restored =
        GroupReceiver::decode_state(&receiver.encode_state().unwrap(), |_| digest_two, commit)
            .unwrap();
    assert_eq!(restored.events_issued(), 3);
}
