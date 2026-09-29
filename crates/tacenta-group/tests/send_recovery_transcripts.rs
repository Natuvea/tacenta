//! Recovery of a `GroupOutbox` from a transcript of durable records, and the immutable fields of
//! a retained send (`crates/tacenta-group/src/send.rs`): trailing bytes in a progress record, a
//! progress record whose context the intent did not produce, records of another group, and a
//! logical ID replayed with other recipients or another roster digest.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made. It uses only the public API of `tacenta-group`.
//!
//! - M123 (`send.rs:249`), M124 (`send.rs:291`): a `TCGP` or `TCGA` record with bytes after its
//!   ciphertext is accepted.
//! - M132 (`send.rs:413`): a progress record for a context the intent did not produce is replayed.
//! - M135 (`send.rs:266`), M136 (`send.rs:296`): a `TCGH` or `TCGA` record of another group is not
//!   skipped.
//! - M137 (`send.rs:604`), M138 (`send.rs:602`): `same_immutable_fields` ignores the recipient
//!   count or the roster digest.
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

fn roster_at(revision: u64, names: &[&str]) -> Roster {
    let mut members: Vec<Member> = names.iter().map(|name| named(name)).collect();
    members.sort_by(Member::canonical_cmp);
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

fn send_and_context() -> (LogicalSend, ApplicationContext) {
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

/// M123 (`send.rs:249`): in `GroupOutbox::recover_from_transcript_at_revision`, the `if
/// !record.rest.is_empty() { return Err(Error::Malformed); }` check in the `b"TCGP"` arm is
/// removed, so a `TCGP` record with bytes after its ciphertext is accepted by recovery. The test
/// accepts the exact record and refuses the same record with one extra byte. The existing
/// `codec_robustness` test mutates single bytes and prefixes but never appends, and no other test
/// appends to a progress record.
#[test]
fn m123_a_tcgp_record_with_trailing_bytes_is_malformed() {
    let (send, context) = send_and_context();
    let exact = vec![intent_record(&send), record(b"TCGP", &context, &[])];
    assert!(GroupOutbox::recover_from_transcript(group(), &exact, commit).is_ok());
    let trailing = vec![intent_record(&send), record(b"TCGP", &context, &[0])];
    assert_eq!(
        GroupOutbox::recover_from_transcript(group(), &trailing, commit).map(|_| ()),
        Err(Error::Malformed)
    );
}

/// M124 (`send.rs:291`): the same check in the `b"TCGA"` arm of
/// `recover_from_transcript_at_revision` is removed, so a `TCGA` record with trailing bytes is
/// accepted.
#[test]
fn m124_a_tcga_record_with_trailing_bytes_is_malformed() {
    let (send, context) = send_and_context();
    let prefix = vec![
        intent_record(&send),
        record(b"TCGP", &context, &[]),
        record(b"TCGH", &context, &[1, 0]),
    ];
    let mut exact = prefix.clone();
    exact.push(record(b"TCGA", &context, &[]));
    assert!(GroupOutbox::recover_from_transcript(group(), &exact, commit).is_ok());
    let mut trailing = prefix;
    trailing.push(record(b"TCGA", &context, &[0]));
    assert_eq!(
        GroupOutbox::recover_from_transcript(group(), &trailing, commit).map(|_| ()),
        Err(Error::Malformed)
    );
}

/// M132 (`send.rs:413`): in `apply_recovered_preparation`, the check `if
/// send.application_context(&context.recipient)? != *context { return Err(Error::Conflict); }` is
/// removed, so a progress record whose context is not the context the logical intent produces for
/// that recipient (here: another payload, with its commitment recomputed so that the commitment
/// check passes) is replayed and the send holds a prepared ciphertext for bytes the intent never
/// produced.
#[test]
fn m132_a_progress_record_for_a_context_the_intent_did_not_produce_is_a_conflict() {
    let (send, context) = send_and_context();
    let honest = vec![intent_record(&send), record(b"TCGP", &context, &[])];
    assert!(GroupOutbox::recover_from_transcript(group(), &honest, commit).is_ok());

    // Same logical ID and recipient, another payload; the record is internally
    // consistent (its commitment matches its own context).
    let tampered = ApplicationContext::new(
        context.group_id,
        context.revision,
        context.roster_digest,
        context.sender.clone(),
        context.recipient.clone(),
        context.logical_sequence,
        b"tampered".to_vec(),
    )
    .unwrap();
    let entries = vec![intent_record(&send), record(b"TCGP", &tampered, &[])];
    assert_eq!(
        GroupOutbox::recover_from_transcript(group(), &entries, commit).map(|_| ()),
        Err(Error::Conflict)
    );
}

fn other_group() -> GroupId {
    GroupId::new(*b"another-group-id")
}

/// A complete transcript of a send in another group: the intent, the prepared
/// ciphertext, the handoff and the relay acceptance.
fn other_groups_transcript() -> Vec<Vec<u8>> {
    let mut members = vec![named("alice"), named("bob")];
    members.sort_by(Member::canonical_cmp);
    let roster = Roster::new(
        other_group(),
        1,
        [0; DIGEST_LEN],
        named("alice"),
        POLICY_VERSION_V1,
        false,
        members,
    )
    .unwrap();
    let send = LogicalSend::new(
        &roster,
        [5; DIGEST_LEN],
        named("alice"),
        0,
        vec![named("bob")],
        b"elsewhere".to_vec(),
    )
    .unwrap();
    let context = send.application_context(&named("bob")).unwrap();
    vec![
        intent_record(&send),
        record(b"TCGP", &context, &[]),
        record(b"TCGH", &context, &[1, 0]),
        record(b"TCGA", &context, &[]),
    ]
}

/// M135 (`send.rs:266`): in `recover_from_transcript_at_revision`, the `TCGH` arm no longer skips a
/// record of another group (`if record.context.group_id != group_id { continue; }` is removed): the
/// record then names a send the outbox never received and recovery fails with `Malformed`. The
/// client filters the transcript by group before it calls the group crate, and the group crate's
/// own skip of another group's `TCGH` and `TCGA` records had no test.
#[test]
fn m135_a_tcgh_record_of_another_group_is_skipped() {
    let foreign = other_groups_transcript();
    // intent, prepared, handoff
    let recovered =
        GroupOutbox::recover_from_transcript(group(), &foreign[..3], commit).expect("skipped");
    assert!(recovered.sends().is_empty());
}

/// M136 (`send.rs:296`): the same for the `TCGA` arm of `recover_from_transcript_at_revision`.
#[test]
fn m136_a_tcga_record_of_another_group_is_skipped() {
    let foreign = other_groups_transcript();
    // A transcript in which the group's own send is followed by the other
    // group's complete history.
    let (send, context) = send_and_context();
    let mut entries = vec![
        intent_record(&send),
        record(b"TCGP", &context, &[]),
        record(b"TCGH", &context, &[1, 0]),
        record(b"TCGA", &context, &[]),
    ];
    entries.extend(foreign);
    let recovered =
        GroupOutbox::recover_from_transcript(group(), &entries, commit).expect("skipped");
    assert_eq!(recovered.sends().len(), 1);
    assert_eq!(
        recovered.sends()[0].recipients()[0].disposition,
        RecipientDisposition::RelayAccepted
    );
}

/// M137 (`send.rs:604`): `same_immutable_fields` no longer compares `recipients.len()`, so a replay
/// of a logical ID with a superset recipient list is a `Duplicate`, not a `Conflict`.
#[test]
fn m137_a_logical_id_replayed_with_more_recipients_is_a_conflict() {
    let mut narrow_members = vec![named("alice"), named("bob")];
    narrow_members.sort_by(Member::canonical_cmp);
    let mut wide_members = vec![named("alice"), named("bob"), named("carol")];
    wide_members.sort_by(Member::canonical_cmp);
    let make = |members: Vec<Member>, recipients: Vec<Member>| {
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
        LogicalSend::new(
            &roster,
            [5; DIGEST_LEN],
            named("alice"),
            0,
            recipients,
            b"hello".to_vec(),
        )
        .unwrap()
    };
    let narrow = make(narrow_members, vec![named("bob")]);
    let wide = make(wide_members, vec![named("bob"), named("carol")]);
    assert_eq!(narrow.id, wide.id);

    let mut outbox = GroupOutbox::new(group());
    assert_eq!(
        outbox.record(narrow.clone()),
        Ok(OutboxDisposition::Inserted)
    );
    assert_eq!(outbox.record(narrow), Ok(OutboxDisposition::Duplicate));
    assert_eq!(outbox.record(wide), Err(Error::Conflict));
}

/// M138 (`send.rs:602`): `same_immutable_fields` no longer compares `roster_digest`, so a replay of
/// a logical ID under another roster digest is a `Duplicate`, not a `Conflict`.
#[test]
fn m138_a_logical_id_replayed_under_another_roster_digest_is_a_conflict() {
    let (first, _) = send_and_context();
    let roster = roster_at(1, &["alice", "bob"]);
    let second = LogicalSend::new(
        &roster,
        [6; DIGEST_LEN], // the first used [5; DIGEST_LEN]
        named("alice"),
        0,
        vec![named("bob")],
        b"hello".to_vec(),
    )
    .unwrap();
    assert_eq!(first.id, second.id);
    let mut outbox = GroupOutbox::new(group());
    assert_eq!(outbox.record(first), Ok(OutboxDisposition::Inserted));
    assert_eq!(outbox.record(second), Err(Error::Conflict));
}
