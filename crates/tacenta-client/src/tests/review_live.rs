//! Live guards of the preparation and dispatch functions, run against the
//! in-process directory and relay with a real provider. Each test that names a
//! refusal also shows that the pairwise state was not touched: the exported
//! state is byte-identical before and after, so the refusal came before any
//! encryption (decision 0134).

use super::*;
use crate::group_control_outbox::Outbox as ControlOutbox;
use crate::group_operations::{
    AuthorityControlState, GroupLiveError, InvitationAdmission,
    commit_group_control_outbox_transition, commit_group_invitation_transition,
    commit_logical_intent, commit_outbox_handoff_reservation, dispatch_outbound_roster_control,
    dispatch_outbox_group_handoff, prepare_authority_roster_control,
    prepare_outbound_roster_control, prepare_outbox_group_recipient, recover_group_control_outbox,
    recover_group_outbox,
};
use crate::operation_store::{
    CommitOutcome, DurableStore, OperationSnapshot, OperationStore, StoreError,
};
use tacenta_group::{
    DIGEST_LEN, GroupId, GroupOutbox, GroupReceiver, Invitation, InvitationBook, InvitationId,
    InvitationStatus, LogicalSend, Member, POLICY_VERSION_V1, RecipientDisposition, Roster,
    RosterView,
};

async fn connect(
    directory: std::net::SocketAddr,
    relay: std::net::SocketAddr,
    user: &str,
) -> DefaultClient {
    DefaultClient::connect(&Config {
        directory,
        relay,
        user: user.into(),
        device: 1,
    })
    .await
    .unwrap()
}

fn member(client: &DefaultClient) -> Member {
    Member::new(client.party.identity_key(), vec![1])
}

fn canonical(mut members: Vec<Member>) -> Vec<Member> {
    members.sort_by(|left, right| {
        left.identity()
            .cmp(right.identity())
            .then_with(|| left.device().cmp(right.device()))
    });
    members
}

fn gid() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}

fn genesis_for(authority: &Member) -> (Roster, [u8; DIGEST_LEN]) {
    let genesis = Roster::new(
        gid(),
        0,
        [0; DIGEST_LEN],
        authority.clone(),
        POLICY_VERSION_V1,
        false,
        vec![authority.clone()],
    )
    .unwrap();
    let digest = tacenta_core::crypto::groups::roster_commitment(&genesis.encode().unwrap());
    (genesis, digest)
}

fn successor(
    authority: &Member,
    revision: u64,
    predecessor: [u8; DIGEST_LEN],
    members: Vec<Member>,
) -> Roster {
    Roster::new(
        gid(),
        revision,
        predecessor,
        authority.clone(),
        POLICY_VERSION_V1,
        false,
        canonical(members),
    )
    .unwrap()
}

/// A store whose next commit outcomes are scripted.
struct Scripted {
    script: std::collections::VecDeque<CommitOutcome>,
    last: Option<OperationSnapshot>,
}

impl Scripted {
    fn new(script: impl IntoIterator<Item = CommitOutcome>) -> Self {
        Self {
            script: script.into_iter().collect(),
            last: None,
        }
    }
}

impl OperationStore for Scripted {
    fn commit(&mut self, snapshot: &OperationSnapshot) -> CommitOutcome {
        let outcome = self.script.pop_front().unwrap_or(CommitOutcome::Committed);
        if outcome == CommitOutcome::Committed {
            self.last = Some(snapshot.clone());
        }
        outcome
    }
    fn recover(&mut self) -> std::result::Result<Option<OperationSnapshot>, StoreError> {
        Ok(self.last.clone())
    }
}

#[tokio::test]
async fn k_c19_a_non_member_never_receives_roster_control() {
    let (directory, relay) = start_server().await;
    let mut alice = connect(directory, relay, "+alice").await;
    let bob = connect(directory, relay, "+bob").await;
    let mallory = connect(directory, relay, "+mallory").await;
    let (a, b, mal) = (member(&alice), member(&bob), member(&mallory));
    let (genesis, digest) = genesis_for(&a);
    let mut view = RosterView::accept_genesis(&a, genesis.clone(), digest).unwrap();
    let mut receiver = GroupReceiver::new(genesis, digest, a.clone());
    let r1 = successor(&a, 1, digest, vec![a.clone(), b.clone()]);
    let mut outbox = ControlOutbox::default();
    let mut store = GroupStore { snapshot: None };
    let mut snapshot = OperationSnapshot::empty(0);
    let before = alice.export_state().await.unwrap();
    assert_eq!(before, alice.export_state().await.unwrap());
    let result = prepare_authority_roster_control(
        &mut alice,
        &mut store,
        &mut snapshot,
        AuthorityControlState {
            view: &mut view,
            receiver: &mut receiver,
            logical_sends: &mut [],
            group_outbox: None,
            outbox: &mut outbox,
            invitation_book: None,
            admission: None,
            control_now: 0,
        },
        &a,
        (&mal, mallory.address()),
        r1,
    )
    .await;
    assert!(matches!(result, Err(GroupLiveError::Policy)), "{result:?}");
    assert_eq!(before, alice.export_state().await.unwrap());
}

#[allow(clippy::type_complexity)]
async fn invited_setup() -> (
    DefaultClient,
    DefaultClient,
    DefaultClient,
    Member,
    Member,
    Member,
    RosterView,
    GroupReceiver,
    InvitationBook,
    GroupStore,
    OperationSnapshot,
    [u8; DIGEST_LEN],
    InvitationId,
) {
    let (directory, relay) = start_server().await;
    let alice = connect(directory, relay, "+alice").await;
    let bob = connect(directory, relay, "+bob").await;
    let carol = connect(directory, relay, "+carol").await;
    let (a, b, c) = (member(&alice), member(&bob), member(&carol));
    let (genesis, digest) = genesis_for(&a);
    let view = RosterView::accept_genesis(&a, genesis.clone(), digest).unwrap();
    let receiver = GroupReceiver::new(genesis, digest, a.clone());
    let id = InvitationId::new([10; 16]);
    let mut book = InvitationBook::new(gid());
    let mut store = GroupStore { snapshot: None };
    let mut snapshot = OperationSnapshot::empty(0);
    let invitation =
        Invitation::new(id, gid(), b.clone(), 0, digest, POLICY_VERSION_V1, 10).unwrap();
    commit_group_invitation_transition(&mut store, &mut snapshot, &mut book, |book| {
        book.create(&a, &a, std::slice::from_ref(&a), invitation.clone(), 0)
            .map(|_| ())
    })
    .unwrap();
    (
        alice, bob, carol, a, b, c, view, receiver, book, store, snapshot, digest, id,
    )
}

#[tokio::test]
async fn k_c18_a_refused_admission_does_not_consume_the_ratchet() {
    let (
        mut alice,
        bob,
        _carol,
        a,
        b,
        _c,
        mut view,
        mut receiver,
        mut book,
        mut store,
        mut snapshot,
        digest,
        id,
    ) = invited_setup().await;
    commit_group_invitation_transition(&mut store, &mut snapshot, &mut book, |book| {
        book.revoke(id, &a, &a, 1).map(|_| ())
    })
    .unwrap();
    let r1 = successor(&a, 1, digest, vec![a.clone(), b.clone()]);
    let mut outbox = ControlOutbox::default();
    let before = alice.export_state().await.unwrap();
    let result = prepare_authority_roster_control(
        &mut alice,
        &mut store,
        &mut snapshot,
        AuthorityControlState {
            view: &mut view,
            receiver: &mut receiver,
            logical_sends: &mut [],
            group_outbox: None,
            outbox: &mut outbox,
            invitation_book: Some(&mut book),
            admission: Some(InvitationAdmission {
                id,
                target: b.clone(),
                now: 2,
            }),
            control_now: 2,
        },
        &a,
        (&b, bob.address()),
        r1,
    )
    .await;
    assert!(matches!(result, Err(GroupLiveError::Policy)));
    assert_eq!(before, alice.export_state().await.unwrap());
}

#[tokio::test]
async fn k_c20_an_admission_target_missing_from_the_successor_is_refused_before_it_encrypts() {
    let (
        mut alice,
        _bob,
        carol,
        a,
        b,
        c,
        mut view,
        mut receiver,
        mut book,
        mut store,
        mut snapshot,
        digest,
        id,
    ) = invited_setup().await;
    commit_group_invitation_transition(&mut store, &mut snapshot, &mut book, |book| {
        book.accept(id, &b, 0, &digest, 1).map(|_| ())
    })
    .unwrap();
    let r1 = successor(&a, 1, digest, vec![a.clone(), c.clone()]);
    let mut outbox = ControlOutbox::default();
    let before = alice.export_state().await.unwrap();
    let result = prepare_authority_roster_control(
        &mut alice,
        &mut store,
        &mut snapshot,
        AuthorityControlState {
            view: &mut view,
            receiver: &mut receiver,
            logical_sends: &mut [],
            group_outbox: None,
            outbox: &mut outbox,
            invitation_book: Some(&mut book),
            admission: Some(InvitationAdmission {
                id,
                target: b.clone(),
                now: 2,
            }),
            control_now: 2,
        },
        &a,
        (&c, carol.address()),
        r1,
    )
    .await;
    assert!(
        matches!(result, Err(GroupLiveError::Policy)),
        "{:?}",
        result.as_ref().map(|_| ())
    );
    assert_eq!(
        book.records()[0].status,
        InvitationStatus::AcceptedPendingAdmission
    );
    assert_eq!(
        before,
        alice.export_state().await.unwrap(),
        "the refusal came after the encryption"
    );
}

#[tokio::test]
async fn a_full_control_outbox_refuses_before_it_encrypts() {
    let (directory, relay) = start_server().await;
    let mut alice = connect(directory, relay, "+alice").await;
    let bob = connect(directory, relay, "+bob").await;
    let (a, b) = (member(&alice), member(&bob));
    let mut outbox = ControlOutbox::default();
    let mut store = GroupStore { snapshot: None };
    let mut snapshot = OperationSnapshot::empty(0);
    // Eight distinct live handoffs to one recipient fill the live bound.
    for revision in 1..=8u64 {
        let roster = successor(
            &a,
            revision,
            [revision as u8; DIGEST_LEN],
            vec![a.clone(), b.clone()],
        );
        prepare_outbound_roster_control(
            &mut alice,
            &mut store,
            &mut snapshot,
            &mut outbox,
            &b,
            bob.address(),
            roster,
        )
        .await
        .unwrap();
    }
    let before = alice.export_state().await.unwrap();
    let ninth = successor(&a, 9, [9; DIGEST_LEN], vec![a.clone(), b.clone()]);
    let result = prepare_outbound_roster_control(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut outbox,
        &b,
        bob.address(),
        ninth,
    )
    .await;
    assert!(
        matches!(result, Err(GroupLiveError::Policy)),
        "{:?}",
        result.as_ref().map(|_| ())
    );
    assert_eq!(before, alice.export_state().await.unwrap());
}

#[tokio::test]
async fn preparing_an_exact_live_control_again_returns_it_without_encrypting() {
    let (directory, relay) = start_server().await;
    let mut alice = connect(directory, relay, "+alice").await;
    let bob = connect(directory, relay, "+bob").await;
    let (a, b) = (member(&alice), member(&bob));
    let mut outbox = ControlOutbox::default();
    let mut store = GroupStore { snapshot: None };
    let mut snapshot = OperationSnapshot::empty(0);
    let roster = successor(&a, 1, [0; DIGEST_LEN], vec![a.clone(), b.clone()]);
    let first = prepare_outbound_roster_control(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut outbox,
        &b,
        bob.address(),
        roster.clone(),
    )
    .await
    .unwrap();
    let before = alice.export_state().await.unwrap();
    let generation = snapshot.generation;
    let again = prepare_outbound_roster_control(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut outbox,
        &b,
        bob.address(),
        roster,
    )
    .await
    .unwrap();
    assert_eq!(again.ciphertext, first.ciphertext);
    assert_eq!(before, alice.export_state().await.unwrap());
    assert_eq!(snapshot.generation, generation, "nothing was published");
}

#[tokio::test]
async fn preparing_for_a_cancelled_recipient_is_refused_before_it_encrypts() {
    let (directory, relay) = start_server().await;
    let mut alice = connect(directory, relay, "+alice").await;
    let bob = connect(directory, relay, "+bob").await;
    let (a, b) = (member(&alice), member(&bob));
    let roster = successor(&a, 1, [0; DIGEST_LEN], vec![a.clone(), b.clone()]);
    let send = LogicalSend::new(
        &roster,
        [7; DIGEST_LEN],
        a.clone(),
        0,
        vec![b.clone()],
        b"cancelled".to_vec(),
    )
    .unwrap();
    let id = send.id.clone();
    let mut store = GroupStore { snapshot: None };
    let mut snapshot = OperationSnapshot::empty(0);
    let mut outbox = GroupOutbox::new(gid());
    commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send).unwrap();
    outbox.cancel_for_newer_roster(2);
    let before = alice.export_state().await.unwrap();
    let result = prepare_outbox_group_recipient(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut outbox,
        &id,
        &b,
        bob.address(),
    )
    .await;
    assert!(matches!(result, Err(GroupLiveError::Policy)));
    assert_eq!(before, alice.export_state().await.unwrap());
    assert!(
        snapshot.provider_state.is_empty(),
        "nothing durable changed"
    );
}

#[tokio::test]
async fn preparing_an_exact_prepared_recipient_again_returns_it_without_encrypting() {
    let (directory, relay) = start_server().await;
    let mut alice = connect(directory, relay, "+alice").await;
    let bob = connect(directory, relay, "+bob").await;
    let (a, b) = (member(&alice), member(&bob));
    let roster = successor(&a, 1, [0; DIGEST_LEN], vec![a.clone(), b.clone()]);
    let send = LogicalSend::new(
        &roster,
        [7; DIGEST_LEN],
        a.clone(),
        0,
        vec![b.clone()],
        b"once".to_vec(),
    )
    .unwrap();
    let id = send.id.clone();
    let mut store = GroupStore { snapshot: None };
    let mut snapshot = OperationSnapshot::empty(0);
    let mut outbox = GroupOutbox::new(gid());
    commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send).unwrap();
    let first = prepare_outbox_group_recipient(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut outbox,
        &id,
        &b,
        bob.address(),
    )
    .await
    .unwrap();
    let before = alice.export_state().await.unwrap();
    let again = prepare_outbox_group_recipient(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut outbox,
        &id,
        &b,
        bob.address(),
    )
    .await
    .unwrap();
    assert_eq!(again.ciphertext, first.ciphertext);
    assert_eq!(before, alice.export_state().await.unwrap());
}

#[tokio::test]
async fn a_second_preparation_after_frozen_neither_succeeds_nor_encrypts() {
    let (directory, relay) = start_server().await;
    let mut alice = connect(directory, relay, "+alice").await;
    let bob = connect(directory, relay, "+bob").await;
    let (a, b) = (member(&alice), member(&bob));
    let roster = successor(&a, 1, [0; DIGEST_LEN], vec![a.clone(), b.clone()]);
    let send = LogicalSend::new(
        &roster,
        [7; DIGEST_LEN],
        a.clone(),
        0,
        vec![b.clone()],
        b"frozen".to_vec(),
    )
    .unwrap();
    let id = send.id.clone();
    // The intent commits; the preparation's publication is in doubt.
    let mut store = DurableStore::new(Scripted::new([
        CommitOutcome::Committed,
        CommitOutcome::Unknown,
    ]));
    let mut snapshot = OperationSnapshot::empty(0);
    let mut outbox = GroupOutbox::new(gid());
    commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send).unwrap();
    let first = prepare_outbox_group_recipient(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut outbox,
        &id,
        &b,
        bob.address(),
    )
    .await;
    assert!(matches!(first, Err(GroupLiveError::Frozen)));
    let after_first = alice.export_state().await.unwrap();
    let second = prepare_outbox_group_recipient(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut outbox,
        &id,
        &b,
        bob.address(),
    )
    .await;
    assert!(
        matches!(second, Err(GroupLiveError::Frozen)),
        "the operation stayed latched"
    );
    assert_eq!(
        after_first,
        alice.export_state().await.unwrap(),
        "the second attempt encrypted again"
    );
    assert_eq!(
        outbox.send(&id).unwrap().recipients()[0].disposition,
        RecipientDisposition::Pending
    );
}

#[tokio::test]
async fn the_final_attempt_is_sent_once_and_recorded_as_relay_accepted() {
    let (directory, relay) = start_server().await;
    let mut alice = connect(directory, relay, "+alice").await;
    let mut bob = connect(directory, relay, "+bob").await;
    let (a, b) = (member(&alice), member(&bob));
    let roster = successor(&a, 1, [0; DIGEST_LEN], vec![a.clone(), b.clone()]);
    let send = LogicalSend::new(
        &roster,
        [7; DIGEST_LEN],
        a.clone(),
        0,
        vec![b.clone()],
        b"third attempt".to_vec(),
    )
    .unwrap();
    let id = send.id.clone();
    let mut store = GroupStore { snapshot: None };
    let mut snapshot = OperationSnapshot::empty(0);
    let mut outbox = GroupOutbox::new(gid());
    commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send).unwrap();
    prepare_outbox_group_recipient(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut outbox,
        &id,
        &b,
        bob.address(),
    )
    .await
    .unwrap();
    commit_outbox_handoff_reservation(&mut store, &mut snapshot, &mut outbox, &id, &b).unwrap();
    commit_outbox_handoff_reservation(&mut store, &mut snapshot, &mut outbox, &id, &b).unwrap();
    // The third reservation is the final attempt: it is recorded as
    // exhausted-unknown before it is sent, sent once, and once the relay has
    // accepted it, recorded as relay-accepted (decision 0135).
    let result = dispatch_outbox_group_handoff(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut outbox,
        &id,
        &b,
        bob.address(),
    )
    .await;
    assert!(result.is_ok(), "{:?}", result.as_ref().map(|_| ()));
    assert_eq!(bob.drain().await.unwrap().len(), 1);
    let progress = &outbox.send(&id).unwrap().recipients()[0];
    assert_eq!(progress.disposition, RecipientDisposition::RelayAccepted);
    assert_eq!(progress.attempts_reserved, 3);
    // The durable record says the same: a restart recovers the acceptance.
    assert_eq!(recover_group_outbox(&snapshot, gid()).unwrap(), outbox);
    // A fourth request is refused before anything reaches the relay.
    let fourth = dispatch_outbox_group_handoff(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut outbox,
        &id,
        &b,
        bob.address(),
    )
    .await;
    assert!(matches!(fourth, Err(GroupLiveError::Policy)));
    assert!(bob.drain().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_final_attempt_that_was_reserved_but_never_accepted_stays_exhausted_and_is_not_resent() {
    let (directory, relay) = start_server().await;
    let mut alice = connect(directory, relay, "+alice").await;
    let mut bob = connect(directory, relay, "+bob").await;
    let (a, b) = (member(&alice), member(&bob));
    let roster = successor(&a, 1, [0; DIGEST_LEN], vec![a.clone(), b.clone()]);
    let send = LogicalSend::new(
        &roster,
        [7; DIGEST_LEN],
        a.clone(),
        0,
        vec![b.clone()],
        b"reserved only".to_vec(),
    )
    .unwrap();
    let id = send.id.clone();
    let mut store = GroupStore { snapshot: None };
    let mut snapshot = OperationSnapshot::empty(0);
    let mut outbox = GroupOutbox::new(gid());
    commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send).unwrap();
    prepare_outbox_group_recipient(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut outbox,
        &id,
        &b,
        bob.address(),
    )
    .await
    .unwrap();
    // Three reservations are committed and nothing is ever sent: the process
    // went away, or the relay never took the bytes. Nothing was accepted.
    for _ in 0..3 {
        commit_outbox_handoff_reservation(&mut store, &mut snapshot, &mut outbox, &id, &b).unwrap();
    }
    let recovered = recover_group_outbox(&snapshot, gid()).unwrap();
    assert_eq!(recovered, outbox);
    assert_eq!(
        recovered.send(&id).unwrap().recipients()[0].disposition,
        RecipientDisposition::ExhaustedUnknown,
        "an unaccepted final attempt is not recorded as accepted"
    );
    // A fourth request is refused before anything reaches the relay.
    let fourth = dispatch_outbox_group_handoff(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut outbox,
        &id,
        &b,
        bob.address(),
    )
    .await;
    assert!(matches!(fourth, Err(GroupLiveError::Policy)));
    assert!(bob.drain().await.unwrap().is_empty());
}

#[tokio::test]
async fn the_control_outbox_records_acceptance_of_the_final_attempt_too() {
    let (directory, relay) = start_server().await;
    let mut alice = connect(directory, relay, "+alice").await;
    let mut bob = connect(directory, relay, "+bob").await;
    let (a, b) = (member(&alice), member(&bob));
    let r1 = successor(&a, 1, [0; DIGEST_LEN], vec![a.clone(), b.clone()]);
    let mut outbox = ControlOutbox::default();
    let mut store = GroupStore { snapshot: None };
    let mut snapshot = OperationSnapshot::empty(0);
    let handoff = prepare_outbound_roster_control(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut outbox,
        &b,
        bob.address(),
        r1,
    )
    .await
    .unwrap();
    for _ in 0..2 {
        commit_group_control_outbox_transition(&mut store, &mut snapshot, &mut outbox, |o| {
            o.reserve(&b, &handoff.payload)
        })
        .unwrap();
    }
    let result = dispatch_outbound_roster_control(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut outbox,
        &b,
        &handoff.payload,
        bob.address(),
    )
    .await;
    assert!(result.is_ok(), "{:?}", result.as_ref().map(|_| ()));
    assert_eq!(bob.drain().await.unwrap().len(), 1);
    let accepted = outbox.handoff(&b, &handoff.payload).unwrap();
    assert_eq!(accepted.disposition, ControlDisposition::RelayAccepted);
    assert_eq!(accepted.attempts_reserved, 3);
    // The durable state carries it and decodes to the same outbox.
    let recovered = recover_group_control_outbox(&snapshot).unwrap();
    assert_eq!(recovered, outbox);
    let fourth = dispatch_outbound_roster_control(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut outbox,
        &b,
        &handoff.payload,
        bob.address(),
    )
    .await;
    assert!(matches!(fourth, Err(GroupLiveError::Policy)));
    assert!(
        bob.drain().await.unwrap().is_empty(),
        "a fourth copy reached the relay"
    );
}

#[tokio::test]
async fn k_k01_a_recipient_binding_whose_identity_is_not_the_routes_is_refused() {
    let (directory, relay) = start_server().await;
    let mut alice = connect(directory, relay, "+alice").await;
    let bob = connect(directory, relay, "+bob").await;
    let carol = connect(directory, relay, "+carol").await;
    let (a, b, c) = (member(&alice), member(&bob), member(&carol));
    let roster = successor(
        &a,
        1,
        [0; DIGEST_LEN],
        vec![a.clone(), b.clone(), c.clone()],
    );
    // The binding says Carol's identity, but the route is Bob's device.
    let send = LogicalSend::new(
        &roster,
        [7; DIGEST_LEN],
        a.clone(),
        0,
        vec![c.clone()],
        b"misrouted".to_vec(),
    )
    .unwrap();
    let id = send.id.clone();
    let mut store = GroupStore { snapshot: None };
    let mut snapshot = OperationSnapshot::empty(0);
    let mut outbox = GroupOutbox::new(gid());
    commit_logical_intent(&mut store, &mut snapshot, &mut outbox, send).unwrap();
    let result = prepare_outbox_group_recipient(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut outbox,
        &id,
        &c,
        bob.address(),
    )
    .await;
    assert!(
        result.is_err(),
        "ciphertext prepared for another identity's route"
    );
    assert_eq!(
        outbox.send(&id).unwrap().recipients()[0].disposition,
        RecipientDisposition::Pending
    );
}

#[tokio::test]
async fn an_exhausted_generation_counter_refuses_every_preparation_before_it_encrypts() {
    let (directory, relay) = start_server().await;
    let mut alice = connect(directory, relay, "+alice").await;
    let bob = connect(directory, relay, "+bob").await;
    let (a, b) = (member(&alice), member(&bob));
    let (genesis, digest) = genesis_for(&a);
    let mut store = GroupStore { snapshot: None };
    let mut snapshot = OperationSnapshot::empty(u64::MAX);
    let before = alice.export_state().await.unwrap();

    // A control handoff to a recipient.
    let mut control = ControlOutbox::default();
    let r1 = successor(&a, 1, digest, vec![a.clone(), b.clone()]);
    let result = prepare_outbound_roster_control(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut control,
        &b,
        bob.address(),
        r1.clone(),
    )
    .await;
    assert!(
        matches!(result, Err(GroupLiveError::Frozen)),
        "{:?}",
        result.as_ref().map(|_| ())
    );
    assert_eq!(before, alice.export_state().await.unwrap());

    // The authority's own installation.
    let mut view = RosterView::accept_genesis(&a, genesis.clone(), digest).unwrap();
    let mut receiver = GroupReceiver::new(genesis, digest, a.clone());
    let result = prepare_authority_roster_control(
        &mut alice,
        &mut store,
        &mut snapshot,
        AuthorityControlState {
            view: &mut view,
            receiver: &mut receiver,
            logical_sends: &mut [],
            group_outbox: None,
            outbox: &mut control,
            invitation_book: None,
            admission: None,
            control_now: 0,
        },
        &a,
        (&b, bob.address()),
        r1.clone(),
    )
    .await;
    assert!(
        matches!(result, Err(GroupLiveError::Frozen)),
        "{:?}",
        result.as_ref().map(|_| ())
    );
    assert_eq!(view.roster().revision, 0);
    assert_eq!(before, alice.export_state().await.unwrap());

    // An application recipient.
    let send = LogicalSend::new(
        &r1,
        [7; DIGEST_LEN],
        a.clone(),
        0,
        vec![b.clone()],
        b"last".to_vec(),
    )
    .unwrap();
    let id = send.id.clone();
    let mut outbox = GroupOutbox::new(gid());
    outbox.record(send).unwrap();
    let result = prepare_outbox_group_recipient(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut outbox,
        &id,
        &b,
        bob.address(),
    )
    .await;
    assert!(
        matches!(result, Err(GroupLiveError::Frozen)),
        "{:?}",
        result.as_ref().map(|_| ())
    );
    assert_eq!(before, alice.export_state().await.unwrap());
}

#[tokio::test]
async fn a_latched_store_refuses_a_control_and_an_installation_before_they_encrypt() {
    let (directory, relay) = start_server().await;
    let mut alice = connect(directory, relay, "+alice").await;
    let bob = connect(directory, relay, "+bob").await;
    let (a, b) = (member(&alice), member(&bob));
    let (genesis, digest) = genesis_for(&a);
    // A write in doubt latches the store; nothing that follows may encrypt.
    let mut store = DurableStore::new(Scripted::new([CommitOutcome::Unknown]));
    let mut snapshot = OperationSnapshot::empty(0);
    assert!(
        crate::group_operations::commit_provider_state(&mut store, &mut snapshot, vec![1]).is_err()
    );
    assert!(store.is_frozen());
    let before = alice.export_state().await.unwrap();

    let mut control = ControlOutbox::default();
    let r1 = successor(&a, 1, digest, vec![a.clone(), b.clone()]);
    let result = prepare_outbound_roster_control(
        &mut alice,
        &mut store,
        &mut snapshot,
        &mut control,
        &b,
        bob.address(),
        r1.clone(),
    )
    .await;
    assert!(
        matches!(result, Err(GroupLiveError::Frozen)),
        "{:?}",
        result.as_ref().map(|_| ())
    );
    assert_eq!(
        before,
        alice.export_state().await.unwrap(),
        "a control was encrypted while latched"
    );

    let mut view = RosterView::accept_genesis(&a, genesis.clone(), digest).unwrap();
    let mut receiver = GroupReceiver::new(genesis, digest, a.clone());
    let result = prepare_authority_roster_control(
        &mut alice,
        &mut store,
        &mut snapshot,
        AuthorityControlState {
            view: &mut view,
            receiver: &mut receiver,
            logical_sends: &mut [],
            group_outbox: None,
            outbox: &mut control,
            invitation_book: None,
            admission: None,
            control_now: 0,
        },
        &a,
        (&b, bob.address()),
        r1,
    )
    .await;
    assert!(
        matches!(result, Err(GroupLiveError::Frozen)),
        "{:?}",
        result.as_ref().map(|_| ())
    );
    assert_eq!(
        before,
        alice.export_state().await.unwrap(),
        "an installation was encrypted while latched"
    );
    assert_eq!(view.roster().revision, 0);
}
