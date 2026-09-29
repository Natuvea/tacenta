//! Guards of `GroupReceiver` (`crates/tacenta-group/src/receive.rs`): which refusal is reported
//! when two apply, that a roster of another group is not installed, and the checks
//! `GroupReceiver::decode_state` makes on a durable receiver state, each tampered on its own.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made. It uses only the public API of `tacenta-group`. The refusal is recorded durably by
//! the client (a code per refusal), so which of two applicable refusals is reported is observable.
//! The earlier tests build receiver states only by `encode_state` and by patching counts, so none
//! of the single fields below was ever wrong on its own; the state builder here writes the layout
//! by hand with each field settable.
//!
//! - M141 (`receive.rs:130`), M142 (`receive.rs:124`): swapped refusal checks in `receive`.
//! - M146 (`receive.rs:167`): `install_accepted_roster` accepts a roster of another group.
//! - M147 (`receive.rs:311`), M148 (`receive.rs:321`), M149 (`receive.rs:356`), M150
//!   (`receive.rs:358`), M151 (`receive.rs:283`), M152 (`receive.rs:362`): a check of
//!   `decode_state` is removed or loosened.
//!
//! The ids (`M###`, `D##`) are those of the single-change mutation run against 97689a0; the
//! `file:line` in each test's doc comment is the change site at that commit.

use tacenta_group::*;

fn group() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}

fn named(name: &str) -> Member {
    Member::new(name.as_bytes().to_vec(), vec![1])
}

fn receiver_for_bob() -> GroupReceiver {
    let mut members = vec![named("alice"), named("bob")];
    members.sort_by(Member::canonical_cmp);
    let roster = Roster::new(
        group(),
        1,
        [0; DIGEST_LEN],
        named("alice"),
        POLICY_VERSION_V1,
        false,
        members,
    )
    .unwrap();
    GroupReceiver::new(roster, [7; DIGEST_LEN], named("bob"))
}

fn context(group_id: GroupId, sender: &str, recipient: &str) -> ApplicationContext {
    ApplicationContext::new(
        group_id,
        1,
        [7; DIGEST_LEN],
        named(sender),
        named(recipient),
        0,
        b"hello".to_vec(),
    )
    .unwrap()
}

/// M141 (`receive.rs:130`): in `GroupReceiver::receive`, the `WrongRecipient` check and the
/// `NotActive` check swap places, so a context for another recipient from a sender that is not
/// active is reported `NotActive` instead of `WrongRecipient`.
#[test]
fn m141_wrong_recipient_is_reported_before_not_active() {
    let mut receiver = receiver_for_bob();
    // Mallory is not in the roster (not active) and writes to Carol, not to Bob.
    let stray = context(group(), "mallory", "carol");
    assert_eq!(
        receiver.receive(&stray, &named("mallory"), [1; DIGEST_LEN]),
        ReceiveDisposition::Rejected(ReceiveRefusal::WrongRecipient)
    );
    // The same sender addressing Bob is NotActive.
    let to_bob = context(group(), "mallory", "bob");
    assert_eq!(
        receiver.receive(&to_bob, &named("mallory"), [1; DIGEST_LEN]),
        ReceiveDisposition::Rejected(ReceiveRefusal::NotActive)
    );
}

/// M142 (`receive.rs:124`): in `GroupReceiver::receive`, the `WrongPeer` check and the `WrongGroup`
/// check swap places, so a context for another group whose sender is not the authenticated peer is
/// reported `WrongGroup` instead of `WrongPeer`.
#[test]
fn m142_wrong_peer_is_reported_before_wrong_group() {
    let mut receiver = receiver_for_bob();
    let other = GroupId::new(*b"another-group-id");
    // A context of another group whose sender is not the authenticated peer.
    let stray = context(other, "alice", "bob");
    assert_eq!(
        receiver.receive(&stray, &named("mallory"), [1; DIGEST_LEN]),
        ReceiveDisposition::Rejected(ReceiveRefusal::WrongPeer)
    );
    // With the right peer it is WrongGroup.
    assert_eq!(
        receiver.receive(&stray, &named("alice"), [1; DIGEST_LEN]),
        ReceiveDisposition::Rejected(ReceiveRefusal::WrongGroup)
    );
}

fn roster(revision: u64, closed: bool) -> Roster {
    let mut members = vec![named("alice"), named("bob")];
    members.sort_by(Member::canonical_cmp);
    Roster::new(
        group(),
        revision,
        [0; DIGEST_LEN],
        named("alice"),
        POLICY_VERSION_V1,
        closed,
        members,
    )
    .unwrap()
}

/// A stand-in for the core's commitments; both sides of a decode use it.
fn commit(bytes: &[u8]) -> [u8; DIGEST_LEN] {
    let mut digest = [0u8; DIGEST_LEN];
    for (index, byte) in bytes.iter().enumerate() {
        digest[index % DIGEST_LEN] ^= byte;
    }
    digest
}

fn put_lp(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn put_member(out: &mut Vec<u8>, member: &Member) {
    put_lp(out, member.identity());
    put_lp(out, member.device());
}

struct Accepted {
    sequence: u64,
    event_id: u64,
}

struct Deferred {
    context: ApplicationContext,
    commitment: [u8; DIGEST_LEN],
}

/// A receiver state for Bob at `roster`, in the layout `GroupReceiver::encode_state`
/// writes (see receive.rs), with each field settable.
fn state(
    roster: &Roster,
    digest: [u8; DIGEST_LEN],
    next_event_id: u64,
    accepted: &[Accepted],
    deferred: &[Deferred],
) -> Vec<u8> {
    let roster_bytes = roster.encode().unwrap();
    let mut out = b"Tacenta Group Receiver State v1".to_vec();
    put_lp(&mut out, &roster_bytes);
    out.extend_from_slice(&digest);
    put_member(&mut out, &named("bob"));
    out.extend_from_slice(&next_event_id.to_be_bytes());
    out.extend_from_slice(&(accepted.len() as u32).to_be_bytes());
    for entry in accepted {
        out.extend_from_slice(&roster.revision.to_be_bytes());
        put_member(&mut out, &named("alice"));
        out.extend_from_slice(&entry.sequence.to_be_bytes());
        out.extend_from_slice(&[9; DIGEST_LEN]);
        out.extend_from_slice(&entry.event_id.to_be_bytes());
    }
    out.extend_from_slice(&(deferred.len() as u32).to_be_bytes());
    for entry in deferred {
        put_lp(&mut out, &entry.context.encode().unwrap());
        out.extend_from_slice(&entry.commitment);
    }
    out
}

fn digest_of(roster: &Roster) -> [u8; DIGEST_LEN] {
    commit(&roster.encode().unwrap())
}

fn deferred_context(revision: u64, payload: &[u8]) -> Deferred {
    let context = ApplicationContext::new(
        group(),
        revision,
        [7; DIGEST_LEN],
        named("alice"),
        named("bob"),
        0,
        payload.to_vec(),
    )
    .unwrap();
    let commitment = commit(&context.encode().unwrap());
    Deferred {
        context,
        commitment,
    }
}

fn decode(bytes: &[u8]) -> Result<GroupReceiver, Error> {
    GroupReceiver::decode_state(bytes, commit, commit)
}

/// Control for the `m147` to `m152` tests below: the untampered states they start
/// from decode, so their refusals come from the one field each of them changes.
#[test]
fn control_states_decode() {
    let r1 = roster(1, false);
    let plain = state(
        &r1,
        digest_of(&r1),
        1,
        &[Accepted {
            sequence: 0,
            event_id: 0,
        }],
        &[],
    );
    assert!(decode(&plain).is_ok());
    let future = state(
        &r1,
        digest_of(&r1),
        0,
        &[],
        &[deferred_context(2, b"later")],
    );
    assert!(decode(&future).is_ok());
}

/// M147 (`receive.rs:311`): in `decode_state`, `event_id >= next_event_id` becomes `event_id >
/// next_event_id`, so an accepted entry whose event ID is the next unused one is accepted.
#[test]
fn m147_an_accepted_entry_cannot_carry_the_next_unused_event_id() {
    let r1 = roster(1, false);
    let bytes = state(
        &r1,
        digest_of(&r1),
        0,
        &[Accepted {
            sequence: 0,
            event_id: 0,
        }],
        &[],
    );
    assert_eq!(decode(&bytes).err(), Some(Error::Malformed));
}

/// M148 (`receive.rs:321`): in `decode_state`, the `item.event_id == event_id` half of the
/// duplicate test is removed, so two accepted entries may share an event ID.
#[test]
fn m148_two_accepted_entries_cannot_share_an_event_id() {
    let r1 = roster(1, false);
    let bytes = state(
        &r1,
        digest_of(&r1),
        2,
        &[
            Accepted {
                sequence: 0,
                event_id: 0,
            },
            Accepted {
                sequence: 1,
                event_id: 0,
            },
        ],
        &[],
    );
    assert_eq!(decode(&bytes).err(), Some(Error::Conflict));
}

/// M149 (`receive.rs:356`): in `decode_state`, `context.revision <= roster.revision` becomes `<`,
/// so a deferred context at the accepted revision (which would have been accepted or refused, never
/// deferred) is accepted.
#[test]
fn m149_a_deferred_context_at_the_accepted_revision_is_refused() {
    let r1 = roster(1, false);
    let bytes = state(
        &r1,
        digest_of(&r1),
        0,
        &[],
        &[deferred_context(1, b"not deferred")],
    );
    assert_eq!(decode(&bytes).err(), Some(Error::Conflict));
}

/// M150 (`receive.rs:358`): in `decode_state`, `commitment != payload_commitment(&context_bytes)`
/// is removed, so the commitment stored with a deferred context is not re-derived.
#[test]
fn m150_a_deferred_commitment_must_be_the_commitment_of_its_context() {
    let r1 = roster(1, false);
    let mut entry = deferred_context(2, b"later");
    entry.commitment = [0; DIGEST_LEN];
    let bytes = state(&r1, digest_of(&r1), 0, &[], &[entry]);
    assert_eq!(decode(&bytes).err(), Some(Error::Conflict));
}

/// M151 (`receive.rs:283`): in `decode_state`, the check that the stored roster digest is the core
/// commitment of the stored roster bytes is removed.
#[test]
fn m151_the_roster_digest_must_be_the_commitment_of_the_roster() {
    let r1 = roster(1, false);
    let bytes = state(&r1, [1; DIGEST_LEN], 0, &[], &[]);
    assert_eq!(decode(&bytes).err(), Some(Error::Conflict));
}

/// M152 (`receive.rs:362`): in `decode_state`, the duplicate-key test for deferred contexts is
/// removed.
#[test]
fn m152_two_deferred_contexts_cannot_share_a_key() {
    let r1 = roster(1, false);
    let bytes = state(
        &r1,
        digest_of(&r1),
        0,
        &[],
        &[deferred_context(2, b"one"), deferred_context(2, b"two")],
    );
    assert_eq!(decode(&bytes).err(), Some(Error::Conflict));
}

/// M146 (`receive.rs:167`): `install_accepted_roster` no longer refuses a roster of another group.
#[test]
fn m146_a_roster_of_another_group_is_not_installed() {
    let r1 = roster(1, false);
    let mut receiver = GroupReceiver::new(r1.clone(), digest_of(&r1), named("bob"));
    let other = Roster::new(
        GroupId::new(*b"another-group-id"),
        2,
        [0; DIGEST_LEN],
        named("alice"),
        POLICY_VERSION_V1,
        false,
        vec![named("alice"), named("bob")],
    )
    .unwrap();
    let before = receiver.clone();
    assert_eq!(
        receiver.install_accepted_roster(other.clone(), digest_of(&other)),
        Err(ReceiveRefusal::WrongGroup)
    );
    assert_eq!(receiver, before);
}
