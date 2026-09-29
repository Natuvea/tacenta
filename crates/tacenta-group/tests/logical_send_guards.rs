//! Guards of `LogicalSend` (`crates/tacenta-group/src/send.rs`) that no earlier test pinned: a
//! handoff cannot be reserved for a recipient that was never prepared, a send needs at least one
//! recipient, and a recovered intent lists one device per identity.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made. It uses only the public API of `tacenta-group`.
//!
//! - D01 (M130 + M131, `send.rs:668` and `send.rs:676`): `reserve_handoff` accepts a `Pending`
//!   recipient.
//! - M127 (`send.rs:452`): `LogicalSend::new` accepts an empty recipient list.
//! - M128 (`send.rs:807`): `validate_recovery_recipients` accepts two devices of one identity.
//!
//! The ids (`M###`, `D##`) are those of the single-change mutation run against 97689a0; the
//! `file:line` in each test's doc comment is the change site at that commit.

use tacenta_group::*;

/// D01 (`send.rs:668` + `send.rs:676`): in `LogicalSend::reserve_handoff`,
/// `RecipientDisposition::Pending => return Err(Error::WrongDisposition)` becomes `Pending => {}`
/// (M130) and the `progress.ciphertext.is_none()` guard is removed (M131). Each change alone is
/// redundant with the other (a pending recipient has no ciphertext), so each alone survives every
/// other test; together a recipient that was never prepared can reserve a handoff: it reports
/// `HandedOff` with one attempt and has no ciphertext to hand off. Before this test no test
/// reserved a handoff for a recipient that was still `Pending`.
#[test]
fn d01_a_recipient_that_was_never_prepared_cannot_reserve_a_handoff() {
    let group = GroupId::new(*b"bounded-group-id");
    let alice = Member::new(b"alice".to_vec(), vec![1]);
    let bob = Member::new(b"bob".to_vec(), vec![1]);
    let roster = Roster::new(
        group,
        1,
        [0; DIGEST_LEN],
        alice.clone(),
        POLICY_VERSION_V1,
        false,
        vec![alice.clone(), bob.clone()],
    )
    .unwrap();
    let mut send = LogicalSend::new(
        &roster,
        [5; DIGEST_LEN],
        alice,
        0,
        vec![bob.clone()],
        b"hello".to_vec(),
    )
    .unwrap();
    assert_eq!(
        send.recipients()[0].disposition,
        RecipientDisposition::Pending
    );
    assert_eq!(
        send.reserve_handoff(&bob).err(),
        Some(Error::WrongDisposition)
    );
    assert_eq!(send.recipients()[0].attempts_reserved, 0);
    assert_eq!(
        send.recipients()[0].disposition,
        RecipientDisposition::Pending
    );
}

/// M127 (`send.rs:452`): in `LogicalSend::new`, `if recipients.is_empty() { return
/// Err(Error::EmptyRecipients); }` is removed, so a logical send with no recipient is created (and
/// is already terminal, since `is_terminal` is `all()` over an empty list). `decode_intent` has its
/// own empty-recipient check (M125); `new` had none pinned.
#[test]
fn m127_a_send_with_no_recipient_is_refused() {
    let group = GroupId::new(*b"bounded-group-id");
    let alice = Member::new(b"alice".to_vec(), vec![1]);
    let bob = Member::new(b"bob".to_vec(), vec![1]);
    let roster = Roster::new(
        group,
        1,
        [0; DIGEST_LEN],
        alice.clone(),
        POLICY_VERSION_V1,
        false,
        vec![alice.clone(), bob.clone()],
    )
    .unwrap();
    assert!(
        LogicalSend::new(
            &roster,
            [5; DIGEST_LEN],
            alice.clone(),
            0,
            vec![bob],
            b"hi".to_vec()
        )
        .is_ok()
    );
    assert_eq!(
        LogicalSend::new(
            &roster,
            [5; DIGEST_LEN],
            alice,
            0,
            Vec::new(),
            b"hi".to_vec()
        )
        .err(),
        Some(Error::EmptyRecipients)
    );
}

fn put_lp(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn put_member(out: &mut Vec<u8>, member: &Member) {
    put_lp(out, member.identity());
    put_lp(out, member.device());
}

/// The canonical intent of a send to `recipients`, in the layout `encode_intent`
/// writes (see send.rs), built by hand so that the recipient list can be any list.
fn intent(recipients: &[Member]) -> Vec<u8> {
    let mut out = b"Tacenta Group Logical Send v1".to_vec();
    put_lp(&mut out, b"bounded-group-id");
    out.extend_from_slice(&1u64.to_be_bytes());
    put_member(&mut out, &Member::new(b"alice".to_vec(), vec![1]));
    out.extend_from_slice(&0u64.to_be_bytes());
    put_lp(&mut out, &[5; DIGEST_LEN]);
    put_lp(&mut out, b"hello");
    out.extend_from_slice(&(recipients.len() as u32).to_be_bytes());
    for recipient in recipients {
        put_member(&mut out, recipient);
    }
    out
}

/// M128 (`send.rs:807`): in `validate_recovery_recipients`, `if
/// !identities.insert(recipient.identity()) { return Err(Error::NonCanonical); }` is replaced by
/// `let _ = identities.insert(..)`, so a recovered intent may list two devices of one identity as
/// recipients. (The same check in `validate_recipients` is M129, which is equivalent: the
/// recipients must be members of a roster and a roster holds one device per identity. The recovery
/// path has no roster, so this check is the only one there.)
#[test]
fn m128_a_recovered_intent_cannot_list_two_devices_of_one_identity() {
    let bob1 = Member::new(b"bob".to_vec(), vec![1]);
    let bob2 = Member::new(b"bob".to_vec(), vec![2]);
    let carol = Member::new(b"carol".to_vec(), vec![1]);
    // Control: distinct identities in canonical order decode.
    assert!(LogicalSend::decode_intent(&intent(&[bob1.clone(), carol])).is_ok());
    // Strictly increasing under the canonical order, but one identity twice.
    assert_eq!(
        LogicalSend::decode_intent(&intent(&[bob1, bob2])).err(),
        Some(Error::NonCanonical)
    );
}
