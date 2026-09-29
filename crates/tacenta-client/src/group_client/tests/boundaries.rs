//! The bounded profile's boundaries, driven through `GroupClient` against the
//! in-process directory and relay with a real provider. Every peer identity and
//! state effect below is produced by the provider's outcome; no test hands one to
//! the coordinator. Each limit is stated as a literal number at the edge and one
//! past it, so raising or lowering a constant fails a test.
//!
//! Messages that no honest `GroupClient` would send (a stale sender, a replayed
//! ciphertext, a future revision) are sent with the plain client, which is what
//! a stale or hostile peer has.

use super::*;
use crate::group_operations::{
    commit_logical_intent, dispatch_outbox_group_handoff, prepare_outbox_group_recipient,
    recover_group_outbox,
};

fn app_bytes(
    revision: u64,
    digest: [u8; DIGEST_LEN],
    sender: &Member,
    recipient: &Member,
    sequence: u64,
    payload: &[u8],
) -> Vec<u8> {
    GroupPayload::Application(
        ApplicationContext::new(
            gid(),
            revision,
            digest,
            sender.clone(),
            recipient.clone(),
            sequence,
            payload.to_vec(),
        )
        .unwrap(),
    )
    .encode()
    .unwrap()
}

/// Sends `bytes` as a group-class message from `from` to `to`, as a peer that
/// is not running the coordinator would.
async fn raw_send(from: &mut GroupClient, to: &DeviceAddr, bytes: &[u8]) {
    from.client.send_as(to, bytes, Kind::Group).await.unwrap();
}

/// What the one item `receiver` was sent did.
async fn sole_outcome(receiver: &mut GroupClient) -> GroupOutcome {
    let inbound = receiver.receive(0).await.unwrap();
    assert_eq!(inbound.items.len(), 1, "{inbound:?}");
    assert_eq!(inbound.dropped, 0);
    inbound.items[0].outcome.clone()
}

/// Alice (the authority), Bob and Carol, all members at revision 1.
struct Trio {
    alice: GroupClient,
    alice_store: SharedStore,
    bob: GroupClient,
    bob_store: SharedStore,
    bob_config: Config,
    carol: GroupClient,
    alice_member: Member,
    bob_member: Member,
    carol_member: Member,
    bob_route: DeviceAddr,
    carol_route: DeviceAddr,
}

async fn trio() -> Trio {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let bob_config = config(directory, relay, "+bob", 1);
    let (mut bob, bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let (mut carol, _carol_store) = joined(directory, relay, "+carol", &alice_member).await;
    let (bob_member, carol_member) = (bob.member().unwrap(), carol.member().unwrap());
    let (bob_route, carol_route) = (route(&bob), route(&carol));
    let r1 = alice
        .next_roster(vec![
            alice_member.clone(),
            bob_member.clone(),
            carol_member.clone(),
        ])
        .unwrap();
    alice
        .install_roster(
            r1,
            &[
                (bob_member.clone(), bob_route.clone()),
                (carol_member.clone(), carol_route.clone()),
            ],
            None,
            0,
        )
        .await
        .unwrap();
    for member in [&mut bob, &mut carol] {
        assert_eq!(
            sole_roster_disposition(&member.receive(0).await.unwrap()),
            RosterDisposition::Accepted
        );
        assert_eq!(member.roster().unwrap().revision, 1);
    }
    Trio {
        alice,
        alice_store,
        bob,
        bob_store,
        bob_config,
        carol,
        alice_member,
        bob_member,
        carol_member,
        bob_route,
        carol_route,
    }
}

// ---------------------------------------------------------------------------
// A member removed while a message is in flight
// ---------------------------------------------------------------------------

/// Alice has a message in flight to Bob and Carol: her intent is committed,
/// Bob's copy has been prepared and accepted by the relay, and Carol's has not
/// been prepared yet (a fan-out that was cut short). Then Alice removes Bob.
/// The in-flight state is made with the coordinator's own preparation and
/// dispatch functions, which `send_group` would have run for Carol next.
async fn removal_with_a_message_in_flight(t: &mut Trio) -> LogicalMessageId {
    let id = {
        let GroupClient {
            client,
            store,
            snapshot,
            group,
            ..
        } = &mut t.alice;
        let state = group.as_mut().unwrap();
        let view = state.view.as_ref().unwrap();
        let mut recipients = vec![t.bob_member.clone(), t.carol_member.clone()];
        recipients.sort_by(Member::canonical_cmp);
        let send = LogicalSend::new(
            view.roster(),
            *view.digest(),
            state.local.clone(),
            0,
            recipients,
            b"in flight".to_vec(),
        )
        .unwrap();
        let id = send.id.clone();
        commit_logical_intent(store, snapshot, &mut state.outbox, send).unwrap();
        prepare_outbox_group_recipient(
            client,
            store,
            snapshot,
            &mut state.outbox,
            &id,
            &t.bob_member,
            &t.bob_route,
        )
        .await
        .unwrap();
        dispatch_outbox_group_handoff(
            client,
            store,
            snapshot,
            &mut state.outbox,
            &id,
            &t.bob_member,
            &t.bob_route,
        )
        .await
        .unwrap();
        let progress = state.outbox.send(&id).unwrap().recipients();
        let of = |member: &Member| progress.iter().find(|p| &p.recipient == member).unwrap();
        assert_eq!(
            of(&t.bob_member).disposition,
            RecipientDisposition::RelayAccepted
        );
        assert_eq!(
            of(&t.carol_member).disposition,
            RecipientDisposition::Pending
        );
        id
    };
    let r2 = t
        .alice
        .next_roster(vec![t.alice_member.clone(), t.carol_member.clone()])
        .unwrap();
    let install = t
        .alice
        .install_roster(
            r2,
            &[
                (t.bob_member.clone(), t.bob_route.clone()),
                (t.carol_member.clone(), t.carol_route.clone()),
            ],
            None,
            0,
        )
        .await
        .unwrap();
    assert_eq!(install.disposition, RosterDisposition::Accepted);
    assert_eq!(install.delivered.len(), 2);
    assert!(install.pending.is_empty());
    id
}

#[tokio::test]
async fn removal_in_flight_authority_side_cancels_what_was_unsent_and_keeps_what_was_accepted() {
    let mut t = trio().await;
    let id = removal_with_a_message_in_flight(&mut t).await;

    // The message was at revision 1 and the roster is now revision 2. Bob's
    // copy was already accepted by the relay and stays as evidence; Carol's
    // unsent copy is cancelled, with no ciphertext ever made for it.
    let outbox = &t.alice.group.as_ref().unwrap().outbox;
    let progress = outbox.send(&id).unwrap().recipients();
    let of = |member: &Member| progress.iter().find(|p| &p.recipient == member).unwrap();
    assert_eq!(
        of(&t.bob_member).disposition,
        RecipientDisposition::RelayAccepted
    );
    assert_eq!(
        of(&t.carol_member).disposition,
        RecipientDisposition::Cancelled
    );
    assert_eq!(of(&t.carol_member).attempts_reserved, 0);
    assert!(of(&t.carol_member).ciphertext.is_none());
    // What is durable is what is live.
    let durable = t.alice_store.durable().unwrap();
    assert_eq!(&recover_group_outbox(&durable, gid()).unwrap(), outbox);

    // Nothing is left to drive, so Carol is never sent the cancelled message.
    assert_eq!(
        t.alice
            .dispatch_pending_group_sends(&[
                (t.bob_member.clone(), t.bob_route.clone()),
                (t.carol_member.clone(), t.carol_route.clone()),
            ])
            .await
            .unwrap(),
        0
    );
    let inbound = t.carol.receive(0).await.unwrap();
    assert!(inbound.events().is_empty(), "{inbound:?}");
    assert_eq!(
        sole_roster_disposition(&inbound),
        RosterDisposition::Accepted
    );

    // And Alice can no longer send to Bob.
    assert!(matches!(
        t.alice
            .send_group(
                &[(t.bob_member.clone(), t.bob_route.clone())],
                b"x".to_vec()
            )
            .await,
        Err(GroupError::Policy)
    ));
}

#[tokio::test]
async fn removal_in_flight_recipient_side_accepts_what_preceded_the_removal_and_refuses_what_follows()
 {
    let mut t = trio().await;
    let r1_digest = t.bob.roster_digest().unwrap();
    // Bob, who is about to be removed, sends Carol a message that is still in
    // Carol's queue when the removal arrives behind it.
    let before = app_bytes(
        1,
        r1_digest,
        &t.bob_member,
        &t.carol_member,
        0,
        b"sent before the removal",
    );
    raw_send(&mut t.bob, &t.carol_route, &before).await;
    removal_with_a_message_in_flight(&mut t).await;

    // Carol's queue is [Bob's message, the removal]: she accepts the first as
    // an event at revision 1, then applies revision 2.
    let inbound = t.carol.receive(0).await.unwrap();
    let events = inbound.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].payload, b"sent before the removal");
    assert_eq!(events[0].sender, t.bob_member);
    assert_eq!(inbound.items.len(), 2);
    assert!(matches!(
        inbound.items[1].outcome,
        GroupOutcome::Roster {
            disposition: RosterDisposition::Accepted,
            ..
        }
    ));
    assert_eq!(t.carol.roster().unwrap().revision, 2);

    // A message Bob sends after Carol applied the removal is refused, whatever
    // revision it claims: its sender is not an active member.
    let after = app_bytes(
        1,
        r1_digest,
        &t.bob_member,
        &t.carol_member,
        1,
        b"sent after the removal",
    );
    raw_send(&mut t.bob, &t.carol_route, &after).await;
    assert_eq!(
        sole_outcome(&mut t.carol).await,
        GroupOutcome::Rejected(ReceiveRefusal::NotActive)
    );

    // Bob's own queue is [Alice's message at revision 1, the removal]: he
    // accepts the message, which was sent while he was a member, then applies
    // the removal and is no longer a member.
    let inbound = t.bob.receive(0).await.unwrap();
    let events = inbound.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].payload, b"in flight");
    assert_eq!(inbound.items.len(), 2);
    assert!(matches!(
        inbound.items[1].outcome,
        GroupOutcome::Roster {
            disposition: RosterDisposition::Accepted,
            ..
        }
    ));
    assert_eq!(t.bob.roster().unwrap().revision, 2);
    let restored = t.bob.group.as_ref().unwrap().receiver.as_ref().unwrap();
    assert_eq!(restored.status(), tacenta_group::ReceiverStatus::NotMember);

    // A message addressed to Bob after that is refused, and a restart does not
    // bring him back: the durable receiver is the terminal one.
    let r2_digest = t.carol.roster_digest().unwrap();
    let late = app_bytes(2, r2_digest, &t.alice_member, &t.bob_member, 1, b"too late");
    raw_send(&mut t.alice, &t.bob_route, &late).await;
    assert_eq!(
        sole_outcome(&mut t.bob).await,
        GroupOutcome::Rejected(ReceiveRefusal::NotActive)
    );
    drop(t.bob);
    let mut bob = restart(&t.bob_config, &t.bob_store).await;
    bob.join_group(genesis_of(&t.alice_member), t.alice_member.clone())
        .unwrap();
    raw_send(&mut t.alice, &t.bob_route, &late).await;
    assert_eq!(
        sole_outcome(&mut bob).await,
        GroupOutcome::Rejected(ReceiveRefusal::NotActive)
    );
}

// ---------------------------------------------------------------------------
// Replay: duplicates, the dedup window and a restore
// ---------------------------------------------------------------------------

/// Alice and Bob at revision 1, with a plain second handle on Alice's identity
/// for the messages a peer that is not running the coordinator would send.
struct Pair {
    alice: GroupClient,
    bob: GroupClient,
    bob_store: SharedStore,
    bob_config: Config,
    alice_member: Member,
    bob_member: Member,
    bob_route: DeviceAddr,
    digest: [u8; DIGEST_LEN],
}

async fn pair() -> Pair {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let bob_config = config(directory, relay, "+bob", 1);
    let (mut bob, bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let bob_member = bob.member().unwrap();
    let bob_route = route(&bob);
    let r1 = alice
        .next_roster(vec![alice_member.clone(), bob_member.clone()])
        .unwrap();
    alice
        .install_roster(r1, &[(bob_member.clone(), bob_route.clone())], None, 0)
        .await
        .unwrap();
    assert_eq!(
        sole_roster_disposition(&bob.receive(0).await.unwrap()),
        RosterDisposition::Accepted
    );
    let digest = bob.roster_digest().unwrap();
    Pair {
        alice,
        bob,
        bob_store,
        bob_config,
        alice_member,
        bob_member,
        bob_route,
        digest,
    }
}

impl Pair {
    /// Alice sends Bob one application context and Bob's outcome is returned.
    async fn deliver(&mut self, revision: u64, sequence: u64, payload: &[u8]) -> GroupOutcome {
        let bytes = app_bytes(
            revision,
            self.digest,
            &self.alice_member,
            &self.bob_member,
            sequence,
            payload,
        );
        raw_send(&mut self.alice, &self.bob_route, &bytes).await;
        sole_outcome(&mut self.bob).await
    }
}

fn event_id_of(outcome: &GroupOutcome) -> u64 {
    match outcome {
        GroupOutcome::Event(event) => event.event_id,
        other => panic!("expected an event, got {other:?}"),
    }
}

#[tokio::test]
async fn a_replayed_ciphertext_and_a_repeated_context_are_refused_and_a_restore_keeps_that() {
    let mut p = pair().await;
    let bytes = app_bytes(1, p.digest, &p.alice_member, &p.bob_member, 0, b"once");
    // The relay delivers one ciphertext twice.
    let prepared = p
        .alice
        .client
        .prepare_send_as(&p.bob_route, &bytes, Kind::Group)
        .await
        .unwrap();
    p.alice
        .client
        .dispatch_prepared_send(&prepared)
        .await
        .unwrap();
    p.alice
        .client
        .dispatch_prepared_send(&prepared)
        .await
        .unwrap();
    let inbound = p.bob.receive(0).await.unwrap();
    let events = inbound.events();
    assert_eq!(events.len(), 1, "the first copy is one event");
    assert_eq!(events[0].event_id, 0);
    assert_eq!(events[0].payload, b"once");
    assert_eq!(
        inbound.dropped, 1,
        "the second copy is refused by the provider"
    );

    // Bob restarts from what he committed and the relay delivers it a third
    // time: the provider's replay protection came back with the state.
    drop(p.bob);
    let mut bob = restart(&p.bob_config, &p.bob_store).await;
    bob.join_group(genesis_of(&p.alice_member), p.alice_member.clone())
        .unwrap();
    p.alice
        .client
        .dispatch_prepared_send(&prepared)
        .await
        .unwrap();
    let inbound = bob.receive(0).await.unwrap();
    assert!(inbound.events().is_empty());
    assert_eq!(
        inbound.dropped, 1,
        "the replay after the restore is refused"
    );

    // The same context in a fresh ciphertext is a duplicate with the same event
    // ID, after the restore too; changed content under it is a conflict.
    raw_send(&mut p.alice, &p.bob_route, &bytes).await;
    assert_eq!(
        sole_outcome(&mut bob).await,
        GroupOutcome::Duplicate { event_id: 0 }
    );
    let changed = app_bytes(1, p.digest, &p.alice_member, &p.bob_member, 0, b"changed");
    raw_send(&mut p.alice, &p.bob_route, &changed).await;
    assert_eq!(
        sole_outcome(&mut bob).await,
        GroupOutcome::Rejected(ReceiveRefusal::Conflict)
    );
}

#[tokio::test]
async fn the_dedup_window_is_64_sequences_on_the_live_receive_path() {
    let mut p = pair().await;
    // Sequence 100 is accepted. The window is 64 sequences: 36 + 64 = 100 is
    // expired, 37 + 64 = 101 is inside it.
    assert_eq!(event_id_of(&p.deliver(1, 100, b"a").await), 0);
    assert_eq!(
        p.deliver(1, 36, b"b").await,
        GroupOutcome::Rejected(ReceiveRefusal::SequenceExpired)
    );
    assert_eq!(event_id_of(&p.deliver(1, 37, b"c").await), 1);
    // Both accepted sequences are duplicates with their own event IDs.
    assert_eq!(
        p.deliver(1, 100, b"a").await,
        GroupOutcome::Duplicate { event_id: 0 }
    );
    assert_eq!(
        p.deliver(1, 37, b"c").await,
        GroupOutcome::Duplicate { event_id: 1 }
    );
    // The window moves with the highest sequence: after 164, 100 has expired
    // and 101 has not.
    assert_eq!(event_id_of(&p.deliver(1, 164, b"d").await), 2);
    assert_eq!(
        p.deliver(1, 100, b"a").await,
        GroupOutcome::Rejected(ReceiveRefusal::SequenceExpired)
    );
    assert_eq!(event_id_of(&p.deliver(1, 101, b"e").await), 3);
}

#[tokio::test]
async fn the_future_window_is_two_revisions_and_the_queue_holds_four_across_a_restart() {
    let mut p = pair().await;
    // Revision 1 is current. Revision 3 is the last that is held, revision 4 is
    // refused as out of range.
    assert_eq!(p.deliver(3, 0, b"r3s0").await, GroupOutcome::Deferred);
    assert_eq!(
        p.deliver(4, 0, b"r4s0").await,
        GroupOutcome::Rejected(ReceiveRefusal::FutureOutOfRange)
    );
    // Four distinct items fill the queue; a fifth is refused.
    for (revision, sequence) in [(2, 0), (2, 1), (3, 1)] {
        assert_eq!(
            p.deliver(revision, sequence, b"held").await,
            GroupOutcome::Deferred,
            "({revision}, {sequence})"
        );
    }
    assert_eq!(
        p.deliver(3, 2, b"fifth").await,
        GroupOutcome::Rejected(ReceiveRefusal::DeferredFull)
    );

    // The queue is durable: after a restart it is still four, so a fifth is
    // still refused, and an exact repeat of a held item reuses its slot.
    drop(p.bob);
    p.bob = restart(&p.bob_config, &p.bob_store).await;
    p.bob
        .join_group(genesis_of(&p.alice_member), p.alice_member.clone())
        .unwrap();
    assert_eq!(
        p.deliver(3, 2, b"fifth").await,
        GroupOutcome::Rejected(ReceiveRefusal::DeferredFull)
    );
    assert_eq!(p.deliver(2, 0, b"held").await, GroupOutcome::Deferred);
}

// ---------------------------------------------------------------------------
// Outbox and invitation-book limits through the coordinator
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_outbox_holds_eight_live_sends_and_a_finished_send_frees_a_slot() {
    let mut p = pair().await;
    let recipients = [(p.bob_member.clone(), p.bob_route.clone())];
    // Eight live sends: each intent is committed and nothing is driven, so every
    // recipient is still pending. (The coordinator's own commit function makes
    // them; `send_group` would drive each one to the relay at once.)
    {
        let GroupClient {
            store,
            snapshot,
            group,
            ..
        } = &mut p.alice;
        let state = group.as_mut().unwrap();
        for sequence in 0..8u64 {
            let view = state.view.as_ref().unwrap();
            let send = LogicalSend::new(
                view.roster(),
                *view.digest(),
                state.local.clone(),
                sequence,
                vec![p.bob_member.clone()],
                format!("live {sequence}").into_bytes(),
            )
            .unwrap();
            commit_logical_intent(store, snapshot, &mut state.outbox, send).unwrap();
        }
    }
    assert_eq!(p.alice.group.as_ref().unwrap().outbox.sends().len(), 8);
    // A ninth is refused by the outbox, and nothing changed.
    assert!(matches!(
        p.alice.send_group(&recipients, b"ninth".to_vec()).await,
        Err(GroupError::Policy)
    ));
    assert_eq!(p.alice.group.as_ref().unwrap().outbox.sends().len(), 8);

    // Driving them finishes all eight, and that frees the slots: a ninth send is
    // now accepted, with the next sequence.
    assert_eq!(
        p.alice
            .dispatch_pending_group_sends(&recipients)
            .await
            .unwrap(),
        8
    );
    let ninth = p
        .alice
        .send_group(&recipients, b"ninth".to_vec())
        .await
        .unwrap();
    assert_eq!(ninth.id.sequence, 8);
    let inbound = p.bob.receive(0).await.unwrap();
    assert_eq!(inbound.events().len(), 9);
}

#[tokio::test]
async fn sequences_come_from_the_group_crate_and_start_again_at_each_revision() {
    let mut p = pair().await;
    let recipients = [(p.bob_member.clone(), p.bob_route.clone())];
    for expected in 0..2u64 {
        let sent = p
            .alice
            .send_group(&recipients, b"revision 1".to_vec())
            .await
            .unwrap();
        assert_eq!((sent.id.revision, sent.id.sequence), (1, expected));
    }
    // A roster change with the same members is a new revision. Sequences are
    // per revision (0095, 0138), so the first send at revision 2 is sequence 0,
    // not 2.
    let r2 = p
        .alice
        .next_roster(vec![p.alice_member.clone(), p.bob_member.clone()])
        .unwrap();
    p.alice
        .install_roster(r2, &recipients, None, 0)
        .await
        .unwrap();
    let sent = p
        .alice
        .send_group(&recipients, b"revision 2".to_vec())
        .await
        .unwrap();
    assert_eq!((sent.id.revision, sent.id.sequence), (2, 0));
    let inbound = p.bob.receive(0).await.unwrap();
    let payloads: Vec<&[u8]> = inbound
        .events()
        .iter()
        .map(|event| event.payload.as_slice())
        .collect();
    assert_eq!(
        payloads,
        [&b"revision 1"[..], &b"revision 1"[..], &b"revision 2"[..]]
    );
}

#[tokio::test]
async fn the_outbox_keeps_sixteen_finished_sends_and_the_newest_sequence() {
    let mut p = pair().await;
    let recipients = [(p.bob_member.clone(), p.bob_route.clone())];
    // Seventeen sends, each finished before the next: sixteen are kept, the
    // oldest is dropped, and the next sequence still follows the newest.
    for n in 0..17u64 {
        let sent = p
            .alice
            .send_group(&recipients, format!("send {n}").into_bytes())
            .await
            .unwrap();
        assert_eq!(sent.id.sequence, n);
    }
    let outbox = &p.alice.group.as_ref().unwrap().outbox;
    assert_eq!(outbox.sends().len(), 16);
    let sequences: Vec<u64> = outbox.sends().iter().map(|s| s.id.sequence).collect();
    assert_eq!(sequences.first(), Some(&1));
    assert_eq!(sequences.last(), Some(&16));
    let eighteenth = p
        .alice
        .send_group(&recipients, b"send 17".to_vec())
        .await
        .unwrap();
    assert_eq!(eighteenth.id.sequence, 17);
}

#[tokio::test]
async fn the_invitation_book_holds_32_records_and_refuses_a_33rd_through_the_coordinator() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let bob_store = SharedStore::default();
    let bob = coordinator(directory, relay, "+bob", &bob_store).await;
    let (bob_member, bob_route) = (bob.member().unwrap(), route(&bob));
    // Distinct invitations to one target are separate records.
    for n in 1..=32u8 {
        alice
            .invite(
                InvitationId::new([n; 16]),
                &bob_member,
                &bob_route,
                1_000,
                0,
            )
            .await
            .unwrap_or_else(|error| panic!("invitation {n}: {error:?}"));
    }
    assert_eq!(alice.invitations().len(), 32);
    assert!(matches!(
        alice
            .invite(
                InvitationId::new([33; 16]),
                &bob_member,
                &bob_route,
                1_000,
                0
            )
            .await,
        Err(GroupError::Policy)
    ));
    assert_eq!(alice.invitations().len(), 32);
}

// ---------------------------------------------------------------------------
// The ninth member
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_ninth_member_is_refused_on_the_roster_invitation_and_admission_paths() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let genesis = genesis_of(&alice_member);
    // Eight people are invited at genesis: seven will make the group eight
    // members with the authority, and the eighth would be its ninth.
    let mut invitees = Vec::new();
    for n in 1..=8 {
        let store = SharedStore::default();
        let mut invitee = coordinator(directory, relay, &format!("+m{n}"), &store).await;
        invitee.await_group(gid(), alice_member.clone()).unwrap();
        invitees.push(invitee);
    }
    let bindings: Vec<Member> = invitees.iter().map(|m| m.member().unwrap()).collect();
    let routes: Vec<(Member, DeviceAddr)> = invitees
        .iter()
        .zip(&bindings)
        .map(|(invitee, binding)| (binding.clone(), route(invitee)))
        .collect();
    for (n, (binding, route)) in routes.iter().enumerate() {
        alice
            .invite(
                InvitationId::new([n as u8 + 1; 16]),
                binding,
                route,
                1_000,
                0,
            )
            .await
            .unwrap();
    }
    for (n, invitee) in invitees.iter_mut().enumerate() {
        assert_eq!(invitee.receive(1).await.unwrap().items.len(), 1);
        invitee
            .join_group(genesis.clone(), alice_member.clone())
            .unwrap();
        invitee
            .accept_invitation(InvitationId::new([n as u8 + 1; 16]), &route(&alice), 1)
            .await
            .unwrap();
    }
    assert_eq!(alice.receive(2).await.unwrap().items.len(), 8);

    // Seven admissions: the authority and seven members are eight.
    for k in 1..=7usize {
        let mut members = vec![alice_member.clone()];
        members.extend(bindings[..k].iter().cloned());
        let successor = alice.next_roster(members).unwrap();
        let install = alice
            .install_roster(
                successor,
                &routes,
                Some(Admission {
                    id: InvitationId::new([k as u8; 16]),
                    target: bindings[k - 1].clone(),
                }),
                3,
            )
            .await
            .unwrap();
        assert_eq!(install.disposition, RosterDisposition::Accepted, "{k}");
        for invitee in &mut invitees {
            assert_eq!(
                sole_roster_disposition(&invitee.receive(3).await.unwrap()),
                RosterDisposition::Accepted
            );
        }
    }
    assert_eq!(alice.roster().unwrap().revision, 7);
    assert_eq!(alice.roster().unwrap().members.len(), 8);
    let eighth_invitation = InvitationId::new([8; 16]);
    let status = |alice: &GroupClient| {
        alice
            .invitations()
            .iter()
            .find(|invitation| invitation.id == eighth_invitation)
            .unwrap()
            .status
    };
    assert_eq!(status(&alice), InvitationStatus::AcceptedPendingAdmission);

    // Roster path: a roster of nine members cannot be built.
    let mut nine = vec![alice_member.clone()];
    nine.extend(bindings.iter().cloned());
    assert_eq!(nine.len(), 9);
    assert!(matches!(alice.next_roster(nine), Err(GroupError::Policy)));

    // Invitation path: with eight members active a new invitation is refused,
    // even for a person who was invited before.
    assert!(matches!(
        alice
            .invite(
                InvitationId::new([9; 16]),
                &bindings[7],
                &routes[7].1,
                1_000,
                3
            )
            .await,
        Err(GroupError::Policy)
    ));
    assert_eq!(alice.invitations().len(), 8);

    // Admission path: the eighth invitee accepted long ago and is waiting. The
    // successor that would admit them cannot be built (above), and a successor
    // that names the admission without listing the person is refused.
    let same_members = alice.roster().unwrap().members.clone();
    let without_the_ninth = alice.next_roster(same_members).unwrap();
    assert!(matches!(
        alice
            .install_roster(
                without_the_ninth,
                &routes,
                Some(Admission {
                    id: eighth_invitation,
                    target: bindings[7].clone(),
                }),
                4
            )
            .await,
        Err(GroupError::Policy)
    ));

    // Nothing moved: still revision 7, eight members, the invitation waiting.
    assert_eq!(alice.roster().unwrap().revision, 7);
    assert_eq!(alice.roster().unwrap().members.len(), 8);
    assert_eq!(status(&alice), InvitationStatus::AcceptedPendingAdmission);
}
