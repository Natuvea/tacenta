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
