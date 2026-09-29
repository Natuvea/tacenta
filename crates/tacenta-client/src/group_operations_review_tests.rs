//! Tests that pin the guards of the coordinator to literals.
//!
//! Each `k_*` test passes on the code as it stands and is meant to fail when the
//! single guard it names is changed. Three of them (`k_c12`, `k_c18` and `k_k01`)
//! are named for mutants that survive alone, because another layer refuses the
//! same input (0134, 0135); they pin the behaviour through those layers. The
//! bounds are written as numbers, not derived from the constants they check, so
//! raising a constant fails a test (decision 0133).

use super::*;
use crate::group_control_outbox::Disposition as ControlDisposition;
use crate::operation_store::{DurableStore, StoreError};
use tacenta_core::crypto::{Address, CryptoStateEffect, groups::roster_commitment};
use tacenta_group::{
    ApplicationContext, GroupId, GroupOutbox, GroupPayload, GroupReceiver, Invitation,
    InvitationBook, InvitationBootstrap, InvitationId, InvitationRevocation, InvitationStatus,
    LogicalSend, Member, OutboxDisposition, POLICY_VERSION_V1, ReceiveDisposition, ReceiveRefusal,
    RecipientDisposition, Roster, RosterView,
};

/// A store whose next outcomes are scripted; `landed` records what reached
/// durable storage and `attempts` every generation it was asked to publish.
struct Scripted {
    script: std::collections::VecDeque<CommitOutcome>,
    landed: Option<OperationSnapshot>,
    attempts: Vec<u64>,
}

impl Scripted {
    fn new(script: impl IntoIterator<Item = CommitOutcome>) -> Self {
        Self {
            script: script.into_iter().collect(),
            landed: None,
            attempts: Vec::new(),
        }
    }
}

impl OperationStore for Scripted {
    fn commit(&mut self, snapshot: &OperationSnapshot) -> CommitOutcome {
        self.attempts.push(snapshot.generation);
        let outcome = self.script.pop_front().unwrap_or(CommitOutcome::Committed);
        if outcome == CommitOutcome::Committed {
            self.landed = Some(snapshot.clone());
        }
        outcome
    }
    fn recover(&mut self) -> Result<Option<OperationSnapshot>, StoreError> {
        Ok(self.landed.clone())
    }
}

fn committed() -> Scripted {
    Scripted::new([])
}

fn unknown() -> Scripted {
    Scripted::new(std::iter::repeat_n(CommitOutcome::Unknown, 64))
}

fn gid() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}
fn alice() -> Member {
    Member::new(b"alice-key".to_vec(), vec![1])
}
fn bob() -> Member {
    Member::new(b"bob-key".to_vec(), vec![1])
}
fn roster(revision: u64, members: Vec<Member>) -> Roster {
    Roster::new(
        gid(),
        revision,
        [0; 32],
        alice(),
        POLICY_VERSION_V1,
        false,
        members,
    )
    .unwrap()
}
fn genesis() -> Roster {
    roster(0, vec![alice()])
}
fn genesis_digest() -> [u8; 32] {
    roster_commitment(&genesis().encode().unwrap())
}
fn invitation(id: u8, target: Member, source_revision: u64, digest: [u8; 32]) -> Invitation {
    Invitation::new(
        InvitationId::new([id; 16]),
        gid(),
        target,
        source_revision,
        digest,
        POLICY_VERSION_V1,
        100,
    )
    .unwrap()
}
fn bootstrap_plaintext(target: Member, digest: [u8; 32]) -> Vec<u8> {
    let bootstrap = InvitationBootstrap::new(invitation(7, target, 0, digest), genesis()).unwrap();
    GroupPayload::InvitationBootstrap(bootstrap)
        .encode()
        .unwrap()
}
fn input<'a>(plaintext: &'a [u8], identity: &'a [u8], peer: &'a Address) -> GroupReceiveInput<'a> {
    GroupReceiveInput {
        plaintext,
        authenticated_identity: identity,
        peer,
        provider_state: vec![9],
        provider_effect: CryptoStateEffect::Advanced,
    }
}
fn control_payload(revision: u64) -> Vec<u8> {
    GroupPayload::Roster(roster(revision.max(1), vec![alice(), bob()]))
        .encode()
        .unwrap()
}
fn send_number(n: u64) -> LogicalSend {
    LogicalSend::new(
        &roster(1, vec![alice(), bob()]),
        [5; 32],
        alice(),
        n,
        vec![bob()],
        format!("message {n}").into_bytes(),
    )
    .unwrap()
}
fn application_context(sequence: u64) -> ApplicationContext {
    ApplicationContext::new(gid(), 1, [8; 32], alice(), bob(), sequence, vec![0x41; 200]).unwrap()
}

// ---- uncertain writes at the commit sites no earlier test reached ---------

#[test]
fn k_w02_an_unknown_control_reservation_is_frozen_and_changes_nothing() {
    let payload = control_payload(1);
    let mut outbox = ControlOutbox::default();
    outbox
        .record_prepared(bob(), payload.clone(), vec![7, 8])
        .unwrap();
    let before = outbox.clone();
    let mut store = unknown();
    let mut snapshot = OperationSnapshot::empty(1);
    let result =
        commit_group_control_outbox_transition(&mut store, &mut snapshot, &mut outbox, |c| {
            c.reserve(&bob(), &payload)
        });
    assert_eq!(result, Err(GroupOperationError::Frozen));
    assert_eq!(outbox, before);
    assert_eq!(snapshot.generation, 1);
}

#[test]
fn k_w03_an_unknown_prepared_control_is_frozen_and_records_nothing() {
    let mut outbox = ControlOutbox::default();
    let mut store = unknown();
    let mut snapshot = OperationSnapshot::empty(1);
    let result = commit_prepared_control_handoff(
        &mut store,
        &mut snapshot,
        &mut outbox,
        bob(),
        control_payload(1),
        vec![7, 8],
        vec![4, 5, 6],
    );
    assert_eq!(result, Err(GroupOperationError::Frozen));
    assert_eq!(outbox, ControlOutbox::default());
    assert!(snapshot.provider_state.is_empty());
}

#[test]
fn k_w04_an_unknown_authority_revocation_leaves_the_invitation_pending() {
    let mut book = InvitationBook::new(gid());
    book.create(
        &alice(),
        &alice(),
        &[alice()],
        invitation(7, bob(), 0, genesis_digest()),
        0,
    )
    .unwrap();
    let mut outbox = ControlOutbox::default();
    let mut store = unknown();
    let mut snapshot = OperationSnapshot::empty(1);
    let result = commit_authority_invitation_revocation_transition(
        &mut store,
        &mut snapshot,
        &mut book,
        &mut outbox,
        &alice(),
        InvitationId::new([7; 16]),
        1,
    );
    assert_eq!(result.map(|_| ()), Err(GroupOperationError::Frozen));
    assert_eq!(book.records()[0].status, InvitationStatus::Pending);
}

#[test]
fn k_w09_an_unknown_outbox_handoff_reservation_reserves_no_attempt() {
    let mut durable = committed();
    let mut snapshot = OperationSnapshot::empty(1);
    let send = send_number(7);
    let id = send.id.clone();
    let mut outbox = GroupOutbox::new(gid());
    commit_logical_intent(&mut durable, &mut snapshot, &mut outbox, send).unwrap();
    commit_outbox_prepared_ciphertext(
        &mut durable,
        &mut snapshot,
        &mut outbox,
        &id,
        &bob(),
        vec![7, 8],
        vec![1],
    )
    .unwrap();
    let mut doubtful = unknown();
    let result =
        commit_outbox_handoff_reservation(&mut doubtful, &mut snapshot, &mut outbox, &id, &bob());
    assert_eq!(result.map(|_| ()), Err(GroupOperationError::Frozen));
    let progress = &outbox.send(&id).unwrap().recipients()[0];
    assert_eq!(progress.attempts_reserved, 0);
    assert_eq!(progress.disposition, RecipientDisposition::Prepared);
}

#[test]
fn k_w12_an_unknown_malformed_record_is_frozen_not_returned_as_a_disposition() {
    let mut receiver = GroupReceiver::new(roster(1, vec![alice(), bob()]), [8; 32], bob());
    let mut store = unknown();
    let mut snapshot = OperationSnapshot::empty(1);
    let peer = Address::new("alice", 1);
    let result = commit_group_plaintext(
        &mut store,
        &mut snapshot,
        &mut receiver,
        input(b"not a group payload", b"alice-key", &peer),
    );
    assert_eq!(result, Err(GroupOperationError::Frozen));
}

#[test]
fn k_w14_an_unknown_provider_state_commit_is_frozen_and_changes_nothing() {
    let mut store = unknown();
    let mut snapshot = OperationSnapshot::empty(1);
    let before = snapshot.clone();
    assert_eq!(
        commit_provider_state(&mut store, &mut snapshot, vec![1, 2, 3]),
        Err(GroupOperationError::Frozen)
    );
    assert_eq!(snapshot, before);
}

// ---- wrong sender and narrowing at the invitation coordinator -------------

#[test]
fn k_c12_a_bootstrap_from_a_non_authority_peer_is_refused_and_records_no_invitation() {
    let mut book = InvitationBook::new(gid());
    let mut store = committed();
    let mut snapshot = OperationSnapshot::empty(1);
    let plaintext = bootstrap_plaintext(bob(), genesis_digest());
    let peer = Address::new("mallory", 1);
    let result = commit_group_invitation_bootstrap(
        &mut store,
        &mut snapshot,
        &mut book,
        &bob(),
        1,
        input(&plaintext, b"mallory-key", &peer),
    );
    assert_eq!(result.map(|_| ()), Err(GroupOperationError::Policy));
    assert!(book.records().is_empty());
}

#[test]
fn k_c13_a_bootstrap_naming_another_target_is_refused() {
    let mut book = InvitationBook::new(gid());
    let mut store = committed();
    let mut snapshot = OperationSnapshot::empty(1);
    let carol = Member::new(b"carol-key".to_vec(), vec![1]);
    let plaintext = bootstrap_plaintext(carol, genesis_digest());
    let peer = Address::new("alice", 1);
    let result = commit_group_invitation_bootstrap(
        &mut store,
        &mut snapshot,
        &mut book,
        &bob(),
        1,
        input(&plaintext, b"alice-key", &peer),
    );
    assert_eq!(result.map(|_| ()), Err(GroupOperationError::Policy));
    assert!(book.records().is_empty());
}

#[test]
fn k_c14_a_bootstrap_whose_digest_is_not_the_roster_commitment_is_refused() {
    let mut book = InvitationBook::new(gid());
    let mut store = committed();
    let mut snapshot = OperationSnapshot::empty(1);
    let plaintext = bootstrap_plaintext(bob(), [0xEE; 32]);
    let peer = Address::new("alice", 1);
    let result = commit_group_invitation_bootstrap(
        &mut store,
        &mut snapshot,
        &mut book,
        &bob(),
        1,
        input(&plaintext, b"alice-key", &peer),
    );
    assert_eq!(result.map(|_| ()), Err(GroupOperationError::Policy));
    assert!(book.records().is_empty());
}

fn book_with_two_invitations_for_bob() -> InvitationBook {
    let mut book = InvitationBook::new(gid());
    book.create(
        &alice(),
        &alice(),
        &[alice()],
        invitation(1, bob(), 0, genesis_digest()),
        0,
    )
    .unwrap();
    book.create(
        &alice(),
        &alice(),
        &[alice()],
        invitation(2, bob(), 1, [0x22; 32]),
        0,
    )
    .unwrap();
    book
}

fn revocation_plaintext(id: u8, revision: u64, digest: [u8; 32]) -> Vec<u8> {
    GroupPayload::InvitationRevocation(
        InvitationRevocation::new(gid(), InvitationId::new([id; 16]), revision, digest).unwrap(),
    )
    .encode()
    .unwrap()
}

fn revoke_with(
    plaintext: &[u8],
    identity: &[u8],
    device: &str,
) -> (
    InvitationBook,
    Result<InvitationStatus, GroupOperationError>,
) {
    let mut book = book_with_two_invitations_for_bob();
    let mut store = committed();
    let mut snapshot = OperationSnapshot::empty(1);
    let peer = Address::new(device, 1);
    let result = commit_group_invitation_revocation(
        &mut store,
        &mut snapshot,
        &mut book,
        &bob(),
        &alice(),
        1,
        input(plaintext, identity, &peer),
    );
    (book, result)
}

#[test]
fn k_c15_a_revocation_from_a_non_authority_peer_is_refused() {
    let (book, result) = revoke_with(
        &revocation_plaintext(1, 0, genesis_digest()),
        b"mallory-key",
        "mallory",
    );
    assert_eq!(result, Err(GroupOperationError::Policy));
    assert_eq!(book.records()[0].status, InvitationStatus::Pending);
}

#[test]
fn k_c16_a_revocation_naming_one_id_with_anothers_source_tuple_is_refused() {
    let (book, result) = revoke_with(
        &revocation_plaintext(1, 1, [0x22; 32]),
        b"alice-key",
        "alice",
    );
    assert_eq!(result, Err(GroupOperationError::Policy));
    assert_eq!(book.records()[0].status, InvitationStatus::Pending);
}

#[test]
fn k_c17_a_revocation_with_the_wrong_source_tuple_is_refused() {
    let (book, result) = revoke_with(
        &revocation_plaintext(1, 5, [0x33; 32]),
        b"alice-key",
        "alice",
    );
    assert_eq!(result, Err(GroupOperationError::Policy));
    assert_eq!(book.records()[0].status, InvitationStatus::Pending);
}

#[test]
fn k_c05_observer_authorization_needs_a_successor_at_or_after_the_source_revision() {
    let mut book = InvitationBook::new(gid());
    book.create(
        &alice(),
        &alice(),
        &[alice()],
        invitation(1, bob(), 5, [0; 32]),
        0,
    )
    .unwrap();
    let successor = roster(3, vec![alice()]);
    assert!(!recipient_can_observe_invitation_successor(
        Some(&book),
        &successor,
        &bob(),
        1
    ));
    let later = roster(5, vec![alice()]);
    assert!(recipient_can_observe_invitation_successor(
        Some(&book),
        &later,
        &bob(),
        1
    ));
}

#[test]
fn k_c07_an_installed_control_requires_the_roster_authority_as_sender() {
    let mut view = RosterView::accept_genesis(&alice(), genesis(), genesis_digest()).unwrap();
    let r1 = Roster::new(
        gid(),
        1,
        genesis_digest(),
        alice(),
        POLICY_VERSION_V1,
        false,
        vec![alice(), bob()],
    )
    .unwrap();
    let d1 = roster_commitment(&r1.encode().unwrap());
    assert_eq!(
        view.accept_successor(&alice(), r1, d1),
        tacenta_group::RosterDisposition::Accepted
    );
    let mallory = Member::new(b"mallory-key".to_vec(), vec![1]);
    assert!(recipient_can_receive_installed_roster_control(
        &view,
        &alice(),
        &bob()
    ));
    assert!(!recipient_can_receive_installed_roster_control(
        &view,
        &mallory,
        &bob()
    ));
}

// ---- the control outbox: caps, conflicts, order and reclamation -----------

#[test]
fn k_k08_the_control_outbox_holds_eight_live_handoffs_and_refuses_a_ninth() {
    let mut outbox = ControlOutbox::default();
    for revision in 1..=8u64 {
        outbox
            .record_prepared(bob(), control_payload(revision), vec![revision as u8])
            .unwrap();
    }
    assert_eq!(
        outbox.record_prepared(bob(), control_payload(9), vec![9]),
        Err(GroupError::OutboxFull)
    );
}

#[test]
fn a_finished_control_handoff_frees_its_live_slot_and_is_reclaimed_beyond_sixteen() {
    let mut outbox = ControlOutbox::default();
    for revision in 1..=40u64 {
        let payload = control_payload(revision);
        outbox
            .record_prepared(bob(), payload.clone(), vec![revision as u8])
            .unwrap();
        outbox.reserve(&bob(), &payload).unwrap();
        outbox.accept(&bob(), &payload).unwrap();
    }
    // Forty relay-accepted handoffs, and a forty-first is not refused. Only the
    // sixteen most recent remain as evidence.
    assert_eq!(outbox.len_for_tests(), 16);
    assert!(outbox.handoff(&bob(), &control_payload(40)).is_ok());
    assert!(outbox.handoff(&bob(), &control_payload(25)).is_ok());
    assert!(
        outbox.handoff(&bob(), &control_payload(24)).is_err(),
        "the oldest terminal handoffs were dropped"
    );
    outbox
        .record_prepared(bob(), control_payload(41), vec![41])
        .unwrap();
    // Eight live and sixteen terminal is the most it holds.
    for revision in 42..=48u64 {
        outbox
            .record_prepared(bob(), control_payload(revision), vec![revision as u8])
            .unwrap();
    }
    assert_eq!(outbox.len_for_tests(), 24);
    assert_eq!(
        outbox.record_prepared(bob(), control_payload(49), vec![49]),
        Err(GroupError::OutboxFull)
    );
    let state = outbox.encode_state().unwrap();
    assert_eq!(ControlOutbox::decode_state(&state), Ok(outbox));
}

#[test]
fn a_cancelled_control_keeps_its_ciphertext_until_it_is_among_the_oldest_terminal() {
    let payload = control_payload(1);
    let mut outbox = ControlOutbox::default();
    outbox
        .record_prepared(bob(), payload.clone(), vec![7, 8])
        .unwrap();
    outbox.cancel_non_revocation_for_recipient(&bob());
    let handoff = outbox.handoff(&bob(), &payload).unwrap();
    assert_eq!(handoff.disposition, ControlDisposition::Cancelled);
    assert_eq!(handoff.ciphertext, vec![7, 8]);
    assert_eq!(outbox.pending(), Vec::new());
}

#[test]
fn k_k09_the_control_outbox_conflicts_on_a_different_ciphertext_for_the_same_payload() {
    let payload = control_payload(1);
    let mut outbox = ControlOutbox::default();
    outbox
        .record_prepared(bob(), payload.clone(), vec![1, 2])
        .unwrap();
    assert_eq!(
        outbox.record_prepared(bob(), payload, vec![3, 4]),
        Err(GroupError::Conflict)
    );
}

/// The entries of an encoded control-outbox state, each as its own bytes.
fn control_entries(state: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let domain = b"Tacenta Group Control Outbox State v2".len();
    let count = state[domain] as usize;
    let mut cursor = domain + 1;
    let mut entries = Vec::new();
    for _ in 0..count {
        let start = cursor;
        for _ in 0..4 {
            let length = u32::from_be_bytes(state[cursor..cursor + 4].try_into().unwrap()) as usize;
            cursor += 4 + length;
        }
        cursor += 2 + 8;
        entries.push(state[start..cursor].to_vec());
    }
    assert_eq!(cursor, state.len());
    (state[..=domain].to_vec(), entries)
}

#[test]
fn k_k05_control_outbox_state_in_non_canonical_order_is_refused() {
    let mut outbox = ControlOutbox::default();
    outbox
        .record_prepared(bob(), control_payload(1), vec![1])
        .unwrap();
    outbox
        .record_prepared(bob(), control_payload(2), vec![2])
        .unwrap();
    let canonical = outbox.encode_state().unwrap();
    assert_eq!(ControlOutbox::decode_state(&canonical), Ok(outbox));
    let (mut header, entries) = control_entries(&canonical);
    assert_eq!(entries.len(), 2);
    for entry in entries.iter().rev() {
        header.extend_from_slice(entry);
    }
    assert_ne!(header, canonical);
    assert_eq!(
        ControlOutbox::decode_state(&header),
        Err(GroupError::NonCanonical),
        "the canonical re-encoding check, not another one, refuses the reordering"
    );
}

#[test]
fn a_control_outbox_state_with_a_repeated_sequence_or_handoff_is_refused() {
    let mut outbox = ControlOutbox::default();
    outbox
        .record_prepared(bob(), control_payload(1), vec![1])
        .unwrap();
    outbox
        .record_prepared(bob(), control_payload(2), vec![2])
        .unwrap();
    let (mut header, entries) = control_entries(&outbox.encode_state().unwrap());
    header.extend_from_slice(&entries[0]);
    header.extend_from_slice(&entries[0]);
    let count_at = b"Tacenta Group Control Outbox State v2".len();
    header[count_at] = 2;
    assert_eq!(
        ControlOutbox::decode_state(&header),
        Err(GroupError::Malformed)
    );
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn k_k10_k11_snapshot_recovery_refuses_an_unknown_version_and_trailing_bytes() {
    use crate::operation_store::FileOperationStore;
    let path = std::env::temp_dir().join(format!(
        "tacenta-review-{}-{}.bin",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut store = FileOperationStore::new(&path);
    assert_eq!(
        store.commit(&OperationSnapshot::empty(3)),
        CommitOutcome::Committed
    );
    let good = std::fs::read(&path).unwrap();
    let mut bad_version = good.clone();
    bad_version[4] = 3;
    std::fs::write(&path, &bad_version).unwrap();
    assert!(
        FileOperationStore::new(&path).recover().is_err(),
        "unknown snapshot version accepted"
    );
    let mut trailing = good;
    trailing.push(0);
    std::fs::write(&path, &trailing).unwrap();
    assert!(
        FileOperationStore::new(&path).recover().is_err(),
        "trailing bytes accepted"
    );
    crate::operation_store::remove_store_files(&path);
}

// ---- the bounds of the snapshot, as literals (0133) -----------------------

#[test]
fn rejected_traffic_from_any_peer_cannot_grow_the_snapshot_past_its_bounds() {
    let mut receiver = GroupReceiver::new(roster(1, vec![alice(), bob()]), [8; 32], bob());
    let mut store = committed();
    let mut snapshot = OperationSnapshot::empty(1);
    let peer = Address::new("mallory", 1);
    for n in 0..2000u64 {
        // A non-member's authenticated payload, refused as not active.
        let context = ApplicationContext::new(
            gid(),
            1,
            [8; 32],
            Member::new(b"mallory-key".to_vec(), vec![1]),
            bob(),
            n,
            vec![0x41; 1000],
        )
        .unwrap();
        let plaintext = GroupPayload::Application(context).encode().unwrap();
        assert_eq!(
            commit_group_plaintext(
                &mut store,
                &mut snapshot,
                &mut receiver,
                input(&plaintext, b"mallory-key", &peer),
            ),
            Ok(ReceiveDisposition::Rejected(ReceiveRefusal::NotActive))
        );
    }
    assert_eq!(snapshot.inbox.len(), 64);
    assert_eq!(snapshot.dedup.len(), 0, "a refusal is not a dedup entry");
    assert!(
        snapshot.encoded_len().unwrap() < 10_000,
        "2,000 refused 1,000-byte payloads left {} bytes",
        snapshot.encoded_len().unwrap()
    );
}

#[test]
fn a_malformed_group_payload_is_not_retained_and_leaves_forty_one_bytes() {
    let mut receiver = GroupReceiver::new(roster(1, vec![alice(), bob()]), [8; 32], bob());
    let mut store = committed();
    let mut snapshot = OperationSnapshot::empty(1);
    let peer = Address::new("mallory", 1);
    let garbage = vec![0x5a; 900_000];
    for _ in 0..5 {
        assert_eq!(
            commit_group_plaintext(
                &mut store,
                &mut snapshot,
                &mut receiver,
                input(&garbage, b"mallory-key", &peer),
            ),
            Ok(ReceiveDisposition::Rejected(ReceiveRefusal::Malformed))
        );
    }
    assert_eq!(snapshot.inbox.len(), 5);
    for record in &snapshot.inbox {
        assert_eq!(record.len(), 41);
        assert_eq!(&record[..5], b"TCGM\x01");
        assert_eq!(&record[5..9], &900_000u32.to_be_bytes());
    }
    assert!(snapshot.encoded_len().unwrap() < 2_000);
}

#[test]
fn accepted_contexts_are_kept_as_commitments_and_at_most_five_hundred_and_twelve() {
    let mut receiver = GroupReceiver::new(roster(1, vec![alice(), bob()]), [8; 32], bob());
    let mut store = committed();
    let mut snapshot = OperationSnapshot::empty(1);
    for sequence in 0..600u64 {
        assert!(matches!(
            commit_receive_disposition(
                &mut store,
                &mut snapshot,
                &mut receiver,
                &application_context(sequence),
                &alice(),
                vec![1],
                CryptoStateEffect::Advanced,
            ),
            Ok(ReceiveDisposition::Accepted { .. })
        ));
    }
    assert_eq!(snapshot.dedup.len(), 512);
    assert!(snapshot.dedup.iter().all(|entry| entry.len() == 32));
    assert_eq!(snapshot.inbox.len(), 64);
    // The newest commitment is the last one kept.
    let newest = tacenta_core::crypto::groups::payload_commitment(
        &application_context(599).encode().unwrap(),
    );
    assert_eq!(snapshot.dedup.last().unwrap().as_slice(), newest.as_slice());
}

#[test]
fn a_refused_or_duplicate_record_carries_no_context_and_an_accepted_one_does() {
    let mut receiver = GroupReceiver::new(roster(1, vec![alice(), bob()]), [8; 32], bob());
    let mut store = committed();
    let mut snapshot = OperationSnapshot::empty(1);
    let context = application_context(0);
    let encoded = context.encode().unwrap();
    let mut go = |sender: &Member| {
        commit_receive_disposition(
            &mut store,
            &mut snapshot,
            &mut receiver,
            &context,
            sender,
            vec![1],
            CryptoStateEffect::Advanced,
        )
        .unwrap()
    };
    assert!(matches!(go(&alice()), ReceiveDisposition::Accepted { .. }));
    assert!(matches!(go(&alice()), ReceiveDisposition::Duplicate { .. }));
    assert!(matches!(
        go(&bob()),
        ReceiveDisposition::Rejected(ReceiveRefusal::WrongPeer)
    ));
    let contains = |record: &Vec<u8>| record.windows(encoded.len()).any(|w| w == encoded);
    assert!(
        contains(&snapshot.inbox[0]),
        "the accepted record keeps its context"
    );
    assert!(
        !contains(&snapshot.inbox[1]),
        "a duplicate keeps only its commitment"
    );
    assert!(
        !contains(&snapshot.inbox[2]),
        "a refusal keeps only its commitment"
    );
    assert_eq!(snapshot.dedup.len(), 1);
}

#[test]
fn a_checkpoint_replaces_the_previous_one_of_its_kind_and_the_transcript_stays_at_sixty_four() {
    let mut snapshot = OperationSnapshot::empty(0);
    for round in 0..200u8 {
        append_group_control_records(
            &mut snapshot,
            [
                encode_roster_view_record(&[round]).unwrap(),
                encode_invitation_book_record(&[round]).unwrap(),
                encode_control_outbox_record(&[round]).unwrap(),
                encode_group_outbox_cancellation_record(gid(), u64::from(round)),
                vec![b'T', b'C', b'G', b'C', round],
            ],
        );
    }
    let of = |tag: &[u8]| {
        snapshot
            .group_controls
            .iter()
            .filter(|record| record.starts_with(tag))
            .count()
    };
    assert_eq!(of(b"TCGV"), 1);
    assert_eq!(of(b"TCGB"), 1);
    assert_eq!(of(b"TCGO"), 1);
    assert_eq!(of(b"TCGX"), 1);
    assert_eq!(snapshot.group_controls.len(), 64);
    let newest = snapshot
        .group_controls
        .iter()
        .find(|record| record.starts_with(b"TCGV"))
        .unwrap();
    assert_eq!(newest.last(), Some(&199));
}

#[test]
fn k_c25_eviction_keeps_the_newest_cancellation_checkpoint() {
    let mut snapshot = OperationSnapshot::empty(0);
    snapshot
        .group_controls
        .push(encode_group_outbox_cancellation_record(gid(), 2));
    for i in 0..70u8 {
        snapshot
            .group_controls
            .push(vec![b'T', b'C', b'G', b'C', i]);
    }
    append_group_control_records(&mut snapshot, Vec::<Vec<u8>>::new());
    assert_eq!(snapshot.group_controls.len(), 64);
    assert!(
        snapshot
            .group_controls
            .iter()
            .any(|record| record.starts_with(b"TCGX")),
        "cancellation checkpoint evicted"
    );
}

/// Drives one send to relay acceptance with fake ciphertext, so its records
/// are all in the transcript and it is terminal.
fn finish_send(
    store: &mut Scripted,
    snapshot: &mut OperationSnapshot,
    outbox: &mut GroupOutbox,
    sequence: u64,
) -> tacenta_group::LogicalMessageId {
    let send = send_number(sequence);
    let id = send.id.clone();
    commit_logical_intent(store, snapshot, outbox, send).unwrap();
    commit_outbox_prepared_ciphertext(
        store,
        snapshot,
        outbox,
        &id,
        &bob(),
        vec![sequence as u8; 40],
        vec![1],
    )
    .unwrap();
    commit_outbox_handoff_reservation(store, snapshot, outbox, &id, &bob()).unwrap();
    commit_outbox_relay_acceptance(store, snapshot, outbox, &id, &bob()).unwrap();
    id
}

#[test]
fn the_outbox_transcript_keeps_every_live_send_and_only_sixteen_terminal_ones() {
    let mut store = committed();
    let mut snapshot = OperationSnapshot::empty(0);
    let mut outbox = GroupOutbox::new(gid());
    // Three sends are created and left live.
    let mut live = Vec::new();
    for sequence in 0..3u64 {
        let send = send_number(sequence);
        live.push(send.id.clone());
        assert_eq!(
            commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send),
            Ok(OutboxDisposition::Inserted)
        );
    }
    for sequence in 3..40u64 {
        finish_send(&mut store, &mut snapshot, &mut outbox, sequence);
    }
    let terminal = outbox
        .sends()
        .iter()
        .filter(|send| send.is_terminal())
        .count();
    assert_eq!(terminal, 16);
    assert_eq!(outbox.sends().len(), 19);
    for id in &live {
        assert!(outbox.send(id).is_ok(), "a live send was dropped");
    }
    // Sixteen terminal sends of four records each, plus the live intents.
    assert_eq!(snapshot.outbox.len(), 16 * 4 + 3);
    // The live value is what the durable transcript recovers.
    assert_eq!(recover_group_outbox(&snapshot, gid()).unwrap(), outbox);
    // The newest terminal sends are the ones kept.
    assert!(outbox.send(&send_number(39).id).is_ok());
    assert!(outbox.send(&send_number(24).id).is_ok());
    assert!(outbox.send(&send_number(23).id).is_err());
}

#[test]
fn the_outbox_admits_eight_live_sends_and_refuses_a_ninth() {
    let mut store = committed();
    let mut snapshot = OperationSnapshot::empty(0);
    let mut outbox = GroupOutbox::new(gid());
    for sequence in 0..8u64 {
        commit_logical_intent(
            &mut store,
            &mut snapshot,
            &mut outbox,
            send_number(sequence),
        )
        .unwrap();
    }
    assert_eq!(
        commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send_number(8)),
        Err(GroupOperationError::Policy)
    );
    assert_eq!(outbox.sends().len(), 8);
    assert_eq!(snapshot.outbox.len(), 8);
}

#[test]
fn cancellation_by_roster_changes_counts_toward_the_sixteen_terminal_sends() {
    let mut store = committed();
    let mut snapshot = OperationSnapshot::empty(0);
    let mut outbox = GroupOutbox::new(gid());
    let mut view = RosterView::accept_genesis(&alice(), genesis(), genesis_digest()).unwrap();
    let accept = |store: &mut Scripted,
                  snapshot: &mut OperationSnapshot,
                  view: &mut RosterView,
                  outbox: &mut GroupOutbox| {
        let next = Roster::new(
            gid(),
            view.roster().revision + 1,
            *view.digest(),
            alice(),
            POLICY_VERSION_V1,
            false,
            vec![alice(), bob()],
        )
        .unwrap();
        commit_roster_transition(
            store,
            snapshot,
            RosterCommitState {
                view,
                receiver: None,
                provider: None,
                group_outbox: Some(outbox),
                control_outbox: None,
                prepared_control: None,
                invitation_book: None,
                admission: None,
                deferred: None,
            },
            &alice(),
            next,
            &mut [],
        )
        .unwrap();
    };
    accept(&mut store, &mut snapshot, &mut view, &mut outbox);
    let mut sequence = 0u64;
    for _round in 0..4 {
        // Eight live sends at the accepted revision, all cancelled by the next.
        for _ in 0..8 {
            let send = LogicalSend::new(
                view.roster(),
                *view.digest(),
                alice(),
                sequence,
                vec![bob()],
                b"withheld".to_vec(),
            )
            .unwrap();
            sequence += 1;
            commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send).unwrap();
        }
        accept(&mut store, &mut snapshot, &mut view, &mut outbox);
    }
    assert_eq!(sequence, 32);
    assert_eq!(outbox.sends().len(), 16);
    assert!(outbox.sends().iter().all(|send| send.is_terminal()));
    assert_eq!(
        outbox.sends()[0].recipients()[0].disposition,
        RecipientDisposition::Cancelled
    );
    assert_eq!(recover_group_outbox(&snapshot, gid()).unwrap(), outbox);
}

// ---- the latch and the generations (0134) ---------------------------------

#[test]
fn a_durable_store_latches_after_an_unknown_write_and_never_reuses_its_generation() {
    let mut store = DurableStore::new(Scripted::new([CommitOutcome::Unknown]));
    let mut snapshot = OperationSnapshot::empty(7);
    let mut outbox = GroupOutbox::new(gid());
    assert_eq!(
        commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send_number(1)),
        Err(GroupOperationError::Frozen)
    );
    assert!(store.is_frozen());
    // Latched: the second attempt is refused before it reaches the store, and
    // so is every other kind of commit.
    assert_eq!(
        commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send_number(2)),
        Err(GroupOperationError::Frozen)
    );
    assert_eq!(
        commit_provider_state(&mut store, &mut snapshot, vec![1]),
        Err(GroupOperationError::Frozen)
    );
    assert!(outbox.sends().is_empty());
    assert_eq!(snapshot.generation, 7);
    // Recovery lifts the latch; the next attempt is above the one in doubt.
    assert_eq!(store.recover(), Ok(None));
    assert!(!store.is_frozen());
    assert_eq!(
        commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send_number(2)),
        Ok(OutboxDisposition::Inserted)
    );
    assert_eq!(snapshot.generation, 9, "8 was attempted and left in doubt");
}

#[test]
fn a_failed_write_latches_a_durable_store_too() {
    let mut store = DurableStore::new(Scripted::new([CommitOutcome::Failed]));
    let mut snapshot = OperationSnapshot::empty(0);
    assert_eq!(
        commit_provider_state(&mut store, &mut snapshot, vec![1]),
        Err(GroupOperationError::Frozen)
    );
    assert!(store.is_frozen());
}

#[test]
fn a_plain_store_never_latches() {
    let mut store = Scripted::new([CommitOutcome::Unknown]);
    let mut snapshot = OperationSnapshot::empty(0);
    assert_eq!(
        commit_provider_state(&mut store, &mut snapshot, vec![1]),
        Err(GroupOperationError::Frozen)
    );
    assert!(!store.is_frozen());
    assert_eq!(store.next_generation(0), Some(1));
    assert_eq!(store.next_generation(u64::MAX), None);
}

fn other_gid() -> GroupId {
    GroupId::new(*b"another-group-id")
}

#[test]
fn a_cancellation_checkpoint_replaces_only_its_own_groups_previous_one() {
    let mut snapshot = OperationSnapshot::empty(0);
    append_group_control_records(
        &mut snapshot,
        [
            encode_group_outbox_cancellation_record(gid(), 2),
            encode_group_outbox_cancellation_record(other_gid(), 3),
        ],
    );
    assert_eq!(snapshot.group_controls.len(), 2);
    append_group_control_records(
        &mut snapshot,
        [encode_group_outbox_cancellation_record(gid(), 5)],
    );
    assert_eq!(snapshot.group_controls.len(), 2);
    assert_eq!(
        latest_group_outbox_cancellation(&snapshot, gid()),
        Ok(Some(5))
    );
    assert_eq!(
        latest_group_outbox_cancellation(&snapshot, other_gid()),
        Ok(Some(3))
    );
}

#[test]
fn compaction_and_recovery_leave_another_groups_records_alone() {
    let other_roster = Roster::new(
        other_gid(),
        1,
        [0; 32],
        alice(),
        POLICY_VERSION_V1,
        false,
        vec![alice(), bob()],
    )
    .unwrap();
    let mut store = committed();
    let mut snapshot = OperationSnapshot::empty(0);
    let mut other_outbox = GroupOutbox::new(other_gid());
    for sequence in 0..2u64 {
        let send = LogicalSend::new(
            &other_roster,
            [5; 32],
            alice(),
            sequence,
            vec![bob()],
            b"other".to_vec(),
        )
        .unwrap();
        commit_logical_intent(&mut store, &mut snapshot, &mut other_outbox, send).unwrap();
    }
    let mut outbox = GroupOutbox::new(gid());
    for sequence in 0..20u64 {
        finish_send(&mut store, &mut snapshot, &mut outbox, sequence);
    }
    // The first group compacted to its sixteen most recent terminal sends and
    // did not touch the other group's two live sends.
    assert_eq!(outbox.sends().len(), 16);
    assert_eq!(recover_group_outbox(&snapshot, gid()).unwrap(), outbox);
    let recovered_other = recover_group_outbox(&snapshot, other_gid()).unwrap();
    assert_eq!(recovered_other.sends().len(), 2);
    assert_eq!(recovered_other, other_outbox);
}

/// A store that reports itself frozen but would accept every write, to show the
/// coordinator refuses before it commits and not only when the store does.
struct FrozenButWilling {
    commits: usize,
}

impl OperationStore for FrozenButWilling {
    fn commit(&mut self, _snapshot: &OperationSnapshot) -> CommitOutcome {
        self.commits += 1;
        CommitOutcome::Committed
    }
    fn recover(&mut self) -> Result<Option<OperationSnapshot>, StoreError> {
        Ok(None)
    }
    fn is_frozen(&self) -> bool {
        true
    }
}

#[test]
fn a_frozen_store_is_refused_before_any_commit_is_attempted() {
    let mut store = FrozenButWilling { commits: 0 };
    let mut snapshot = OperationSnapshot::empty(1);
    let mut outbox = GroupOutbox::new(gid());
    assert_eq!(
        commit_provider_state(&mut store, &mut snapshot, vec![1]),
        Err(GroupOperationError::Frozen)
    );
    assert_eq!(
        commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send_number(1)),
        Err(GroupOperationError::Frozen)
    );
    assert_eq!(store.commits, 0);
    assert_eq!(snapshot.generation, 1);
}

#[test]
fn a_send_that_exhausts_its_attempts_is_terminal_and_compacted_at_that_reservation() {
    let mut store = committed();
    let mut snapshot = OperationSnapshot::empty(0);
    let mut outbox = GroupOutbox::new(gid());
    // Seventeen sends each reach `exhausted_unknown` at their third
    // reservation, which is the only commit that makes them terminal.
    for sequence in 0..17u64 {
        let send = send_number(sequence);
        let id = send.id.clone();
        commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send).unwrap();
        commit_outbox_prepared_ciphertext(
            &mut store,
            &mut snapshot,
            &mut outbox,
            &id,
            &bob(),
            vec![sequence as u8; 40],
            vec![1],
        )
        .unwrap();
        for _ in 0..3 {
            commit_outbox_handoff_reservation(&mut store, &mut snapshot, &mut outbox, &id, &bob())
                .unwrap();
        }
    }
    assert_eq!(outbox.sends().len(), 16);
    assert!(outbox.send(&send_number(0).id).is_err());
    assert!(outbox.send(&send_number(1).id).is_ok());
    assert_eq!(recover_group_outbox(&snapshot, gid()).unwrap(), outbox);
}
