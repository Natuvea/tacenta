//! Guards for the receiver's quota for deferred contexts from senders the accepted roster does not
//! list (decision 0142). They came from a mutation run of the second fix round.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made.

use tacenta_group::*;

fn group() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}

fn small(name: &str) -> Member {
    Member::new(name.as_bytes().to_vec(), vec![1])
}

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

/// In `unlisted_deferred`, the filter that keeps only the contexts of senders the roster does
/// not list is replaced by one that keeps every deferred context, so two contexts of members use up
/// the quota that is meant for outsiders, and the first outsider finds the room taken. The existing
/// test fills the quota with outsiders first, where the two counts agree.
#[test]
fn deferred_contexts_of_members_do_not_use_up_the_quota_for_unlisted_senders() {
    let (alice, bob) = (small("alice"), small("bob"));
    let mut receiver = GroupReceiver::new(
        Roster::new(
            group(),
            2,
            [0; DIGEST_LEN],
            alice.clone(),
            POLICY_VERSION_V1,
            false,
            vec![alice.clone(), bob.clone()],
        )
        .unwrap(),
        ROSTER_DIGEST,
        bob.clone(),
    );
    let (carol, dave, erin) = (small("carol"), small("dave"), small("erin"));
    let defer = |receiver: &mut GroupReceiver, sender: &Member, sequence: u64| {
        receiver.receive(
            &context_from(sender, &bob, 3, sequence),
            sender,
            [1; DIGEST_LEN],
        )
    };
    // Two slots go to the member.
    assert_eq!(
        defer(&mut receiver, &alice, 0),
        ReceiveDisposition::Deferred
    );
    assert_eq!(
        defer(&mut receiver, &alice, 1),
        ReceiveDisposition::Deferred
    );
    // The other two are open to senders the roster does not list.
    assert_eq!(
        defer(&mut receiver, &carol, 0),
        ReceiveDisposition::Deferred
    );
    assert_eq!(defer(&mut receiver, &dave, 0), ReceiveDisposition::Deferred);
    // And now the queue is full.
    assert_eq!(
        defer(&mut receiver, &erin, 0),
        ReceiveDisposition::Rejected(ReceiveRefusal::DeferredFull)
    );
}
