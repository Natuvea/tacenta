//! Live traces of the group coordinator against the in-process directory,
//! relay and real provider. Every identity and state effect below is produced
//! by the provider; no test hands one to the coordinator.

use super::*;
use crate::tests::start_server;
use crate::{Config, DefaultClient};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tacenta_core::crypto::Address;
use tacenta_group::{RecipientDisposition, RosterRefusal};
use tacenta_wire::Kind;

#[derive(Default)]
struct StoreState {
    snapshot: Option<OperationSnapshot>,
    /// Outcomes for the next commits; committed once it is empty.
    script: VecDeque<CommitOutcome>,
    /// Whether an `Unknown` write reaches durable storage.
    unknown_lands: bool,
    attempted: Vec<u64>,
}

/// An in-memory store that a test can keep a handle to across a "crash".
#[derive(Clone, Default)]
struct SharedStore(Arc<Mutex<StoreState>>);

impl SharedStore {
    fn script(&self, outcomes: impl IntoIterator<Item = CommitOutcome>, unknown_lands: bool) {
        let mut state = self.0.lock().unwrap();
        state.script = outcomes.into_iter().collect();
        state.unknown_lands = unknown_lands;
    }

    fn durable(&self) -> Option<OperationSnapshot> {
        self.0.lock().unwrap().snapshot.clone()
    }

    fn attempted_generations(&self) -> Vec<u64> {
        self.0.lock().unwrap().attempted.clone()
    }
}

impl OperationStore for SharedStore {
    fn commit(&mut self, snapshot: &OperationSnapshot) -> CommitOutcome {
        let mut state = self.0.lock().unwrap();
        state.attempted.push(snapshot.generation);
        let outcome = state.script.pop_front().unwrap_or(CommitOutcome::Committed);
        let lands = match outcome {
            CommitOutcome::Committed => true,
            CommitOutcome::Unknown => state.unknown_lands,
            CommitOutcome::Failed => false,
        };
        if lands {
            state.snapshot = Some(snapshot.clone());
        }
        outcome
    }

    fn recover(&mut self) -> Result<Option<OperationSnapshot>, StoreError> {
        Ok(self.0.lock().unwrap().snapshot.clone())
    }
}

fn config(directory: SocketAddr, relay: SocketAddr, user: &str, device: u8) -> Config {
    Config {
        directory,
        relay,
        user: user.into(),
        device,
    }
}

async fn plain(directory: SocketAddr, relay: SocketAddr, user: &str) -> DefaultClient {
    DefaultClient::connect(&config(directory, relay, user, 1))
        .await
        .unwrap()
}

async fn coordinator(
    directory: SocketAddr,
    relay: SocketAddr,
    user: &str,
    store: &SharedStore,
) -> GroupClient {
    GroupClient::open(plain(directory, relay, user).await, store.clone())
        .await
        .unwrap()
}

/// A coordinator started again from what its store holds, as after a crash.
async fn restart(config: &Config, store: &SharedStore) -> GroupClient {
    let state = recovered_provider_state(&mut store.clone())
        .unwrap()
        .expect("the store holds a snapshot");
    let client = DefaultClient::connect_with_state(config, &state)
        .await
        .unwrap();
    GroupClient::open(client, store.clone()).await.unwrap()
}

fn gid() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}

fn member_of(client: &DefaultClient) -> Member {
    Member::new(client.party.identity_key(), vec![1])
}

fn genesis_of(authority: &Member) -> Roster {
    Roster::new(
        gid(),
        0,
        [0; DIGEST_LEN],
        authority.clone(),
        POLICY_VERSION_V1,
        false,
        vec![authority.clone()],
    )
    .unwrap()
}

fn route(client: &GroupClient) -> DeviceAddr {
    client.address().clone()
}

fn sole_roster_disposition(inbound: &Inbound) -> RosterDisposition {
    match inbound.items.as_slice() {
        [
            GroupReceipt {
                outcome: GroupOutcome::Roster { disposition, .. },
                ..
            },
        ] => *disposition,
        other => panic!("expected exactly one roster item, got {other:?}"),
    }
}

/// A member that has joined the authority's group at genesis.
async fn joined(
    directory: SocketAddr,
    relay: SocketAddr,
    user: &str,
    authority: &Member,
) -> (GroupClient, SharedStore) {
    let store = SharedStore::default();
    let mut member = coordinator(directory, relay, user, &store).await;
    member
        .join_group(genesis_of(authority), authority.clone())
        .unwrap();
    (member, store)
}

mod boundaries;

#[tokio::test]
async fn a_crash_between_receive_and_commit_redelivers_the_group_message() {
    let (directory, relay) = start_server().await;
    let mut alice = plain(directory, relay, "+alice").await;
    let bob_config = config(directory, relay, "+bob", 1);
    let alice_member = member_of(&alice);
    let (mut bob, bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let bob_member = bob.member().unwrap();
    let r1 = bob
        .next_roster(vec![alice_member.clone(), bob_member.clone()])
        .unwrap();
    alice
        .send_as(
            bob.address(),
            &GroupPayload::Roster(r1).encode().unwrap(),
            Kind::Group,
        )
        .await
        .unwrap();

    // The publication of the item's disposition never reaches storage and the
    // process dies: nothing was committed, so nothing may have been acknowledged.
    bob_store.script([CommitOutcome::Unknown], false);
    let inbound = bob.receive(0).await.unwrap();
    assert!(inbound.frozen, "an unknown write freezes the batch");
    assert!(inbound.items.is_empty());
    assert!(matches!(bob.receive(0).await, Err(GroupError::Frozen)));
    drop(bob);

    let mut bob = restart(&bob_config, &bob_store).await;
    bob.join_group(genesis_of(&alice_member), alice_member)
        .unwrap();
    let inbound = bob.receive(0).await.unwrap();
    assert_eq!(
        sole_roster_disposition(&inbound),
        RosterDisposition::Accepted,
        "the relay redelivered the unacknowledged control"
    );
    assert_eq!(bob.roster().unwrap().revision, 1);
}

#[tokio::test]
async fn recovery_resets_the_provider_state_so_the_redelivery_decrypts_again() {
    let (directory, relay) = start_server().await;
    let mut alice = plain(directory, relay, "+alice").await;
    let alice_member = member_of(&alice);
    let (mut bob, bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let bob_member = bob.member().unwrap();
    let r1 = bob
        .next_roster(vec![alice_member.clone(), bob_member])
        .unwrap();
    alice
        .send_as(
            bob.address(),
            &GroupPayload::Roster(r1).encode().unwrap(),
            Kind::Group,
        )
        .await
        .unwrap();

    bob_store.script([CommitOutcome::Failed], false);
    let inbound = bob.receive(0).await.unwrap();
    assert!(inbound.frozen);
    let generation_before = bob.generation();

    // While frozen nothing runs: not a send, not a receive.
    assert!(matches!(
        bob.send_direct(&route_of(&alice), b"nope").await,
        Err(GroupError::Frozen)
    ));
    assert!(matches!(bob.receive(0).await, Err(GroupError::Frozen)));
    assert_eq!(bob.generation(), generation_before);

    // In-process recovery: the party consumed the message key in memory, and
    // only resetting it to the durable state lets the redelivery decrypt.
    bob.recover().await.unwrap();
    assert!(!bob.is_frozen());
    let inbound = bob.receive(0).await.unwrap();
    assert_eq!(
        sole_roster_disposition(&inbound),
        RosterDisposition::Accepted
    );
    assert_eq!(bob.roster().unwrap().revision, 1);
    // The store was asked for generation 1 (the first snapshot), then for 2
    // (the write that failed), and the retry after recovery used a higher
    // number than the one that was in doubt.
    assert_eq!(bob_store.attempted_generations(), vec![1, 2, 3]);
}

fn route_of(client: &DefaultClient) -> DeviceAddr {
    client.address().clone()
}

#[tokio::test]
async fn an_unknown_write_that_landed_is_adopted_by_recovery_and_the_redelivery_is_dropped() {
    let (directory, relay) = start_server().await;
    let mut alice = plain(directory, relay, "+alice").await;
    let alice_member = member_of(&alice);
    let (mut bob, bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let bob_member = bob.member().unwrap();
    let r1 = bob
        .next_roster(vec![alice_member.clone(), bob_member])
        .unwrap();
    alice
        .send_as(
            bob.address(),
            &GroupPayload::Roster(r1).encode().unwrap(),
            Kind::Group,
        )
        .await
        .unwrap();

    // The write reaches storage but Bob is told nothing: durable state now
    // holds revision 1 while the coordinator believes it does not.
    bob_store.script([CommitOutcome::Unknown], true);
    assert!(bob.receive(0).await.unwrap().frozen);
    bob.recover().await.unwrap();
    assert_eq!(
        bob.roster().unwrap().revision,
        1,
        "recovery adopts what landed"
    );

    // The item was never acknowledged, so it comes again; its key is consumed
    // by the adopted state and it is dropped as a replay.
    let inbound = bob.receive(0).await.unwrap();
    assert_eq!(inbound.dropped, 1);
    assert!(inbound.items.is_empty());
    assert!(bob.receive(0).await.unwrap().items.is_empty());
}

#[tokio::test]
async fn the_live_receive_takes_the_peer_and_effect_from_the_provider_outcome() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let bob_member = bob.member().unwrap();
    let mut mallory = plain(directory, relay, "+mallory").await;
    let mut alice_second_device = DefaultClient::connect_with_identity(
        &config(directory, relay, "+alice", 2),
        &alice.client.export_identity(),
    )
    .await
    .unwrap();

    // Alice admits Bob, then sends him an application message.
    let r1 = alice
        .next_roster(vec![alice_member.clone(), bob_member.clone()])
        .unwrap();
    let install = alice
        .install_roster(r1, &[(bob_member.clone(), route(&bob))], None, 0)
        .await
        .unwrap();
    assert_eq!(install.delivered, vec![bob_member.clone()]);
    let inbound = bob.receive(0).await.unwrap();
    assert_eq!(
        sole_roster_disposition(&inbound),
        RosterDisposition::Accepted
    );
    let generation = bob.generation();
    let first = alice
        .send_group(&[(bob_member.clone(), route(&bob))], b"hello bob".to_vec())
        .await
        .unwrap();
    assert_eq!(
        first.recipients[0].disposition,
        RecipientDisposition::RelayAccepted
    );
    let inbound = bob.receive(0).await.unwrap();
    let events = inbound.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].payload, b"hello bob");
    assert_eq!(events[0].sender, alice_member);
    assert!(
        bob.generation() > generation,
        "the disposition was committed"
    );

    let r1_digest = bob.roster_digest().unwrap();
    let claim_alice = |sequence: u64, text: &[u8]| {
        GroupPayload::Application(
            ApplicationContext::new(
                gid(),
                1,
                r1_digest,
                alice_member.clone(),
                bob_member.clone(),
                sequence,
                text.to_vec(),
            )
            .unwrap(),
        )
        .encode()
        .unwrap()
    };

    // Wrong sender: an authenticated non-member claims Alice's binding. The
    // identity Bob's receiver checks is the one the provider authenticated.
    mallory
        .send_as(bob.address(), &claim_alice(5, b"forged"), Kind::Group)
        .await
        .unwrap();
    let inbound = bob.receive(0).await.unwrap();
    assert!(matches!(
        inbound.items.as_slice(),
        [GroupReceipt {
            outcome: GroupOutcome::Rejected(ReceiveRefusal::WrongPeer),
            ..
        }]
    ));

    // Wrong device: Alice's identity on device 2 is authentic but is not the
    // Alice/device-1 member the context names.
    alice_second_device
        .send_as(bob.address(), &claim_alice(6, b"other device"), Kind::Group)
        .await
        .unwrap();
    let inbound = bob.receive(0).await.unwrap();
    assert!(matches!(
        inbound.items.as_slice(),
        [GroupReceipt {
            outcome: GroupOutcome::Rejected(ReceiveRefusal::WrongPeer),
            ..
        }]
    ));

    // The refusals consumed pairwise state and committed it: later valid
    // traffic works, and a restart from the store loses nothing.
    let committed = bob_store.durable().unwrap();
    assert_eq!(committed.generation, bob.generation());
    alice
        .send_group(&[(bob_member.clone(), route(&bob))], b"still fine".to_vec())
        .await
        .unwrap();
    let inbound = bob.receive(0).await.unwrap();
    assert_eq!(inbound.events()[0].payload, b"still fine");
    assert_eq!(inbound.events()[0].event_id, 1);
}

async fn dm_gap(with_dm: bool) -> usize {
    let (directory, relay) = start_server().await;
    let alice_config = config(directory, relay, "+alice", 1);
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let mut bob = plain(directory, relay, "+bob").await;
    let bob_member = member_of(&bob);
    let bob_route = bob.address().clone();
    let r1 = alice
        .next_roster(vec![alice_member.clone(), bob_member.clone()])
        .unwrap();
    alice
        .install_roster(r1, &[(bob_member.clone(), bob_route.clone())], None, 0)
        .await
        .unwrap();
    alice
        .send_group(
            &[(bob_member.clone(), bob_route.clone())],
            b"group 0".to_vec(),
        )
        .await
        .unwrap();
    let mut expected = 2;
    if with_dm {
        alice
            .send_direct(&bob_route, b"direct message")
            .await
            .unwrap();
        expected = 3;
    }
    assert_eq!(bob.receive().await.unwrap().len(), expected);

    // Restart from the snapshot alone.
    drop(alice);
    let mut alice = restart(&alice_config, &alice_store).await;
    alice.create_group(gid()).unwrap();
    let sent = alice
        .send_group(&[(bob_member.clone(), bob_route)], b"group 1".to_vec())
        .await
        .unwrap();
    assert_eq!(
        sent.recipients[0].disposition,
        RecipientDisposition::RelayAccepted
    );
    bob.drain().await.unwrap().len()
}

#[tokio::test]
async fn a_direct_message_between_group_commits_survives_a_restart() {
    assert_eq!(dm_gap(false).await, 1);
    assert_eq!(
        dm_gap(true).await,
        1,
        "the second group message is received after a restart with an interleaved DM"
    );
}

#[tokio::test]
async fn a_received_direct_message_is_committed_before_it_is_acknowledged() {
    let (directory, relay) = start_server().await;
    let mut alice = plain(directory, relay, "+alice").await;
    let bob_store = SharedStore::default();
    let mut bob = coordinator(directory, relay, "+bob", &bob_store).await;
    let bob_config = config(directory, relay, "+bob", 1);
    alice
        .send_as(bob.address(), b"a direct message", Kind::Dm)
        .await
        .unwrap();
    let before = bob_store.durable().unwrap();
    let inbound = bob.receive(0).await.unwrap();
    assert_eq!(inbound.direct.len(), 1);
    assert_eq!(inbound.direct[0].plaintext, b"a direct message");
    assert_eq!(inbound.direct[0].kind, MessageKind::Direct);
    assert!(inbound.items.is_empty());
    let after = bob_store.durable().unwrap();
    assert_eq!(after.generation, before.generation + 1);
    assert_ne!(
        after.provider_state, before.provider_state,
        "the ratchet step of the received message is durable"
    );
    // It was acknowledged: a restart finds nothing waiting.
    drop(bob);
    let mut bob = restart(&bob_config, &bob_store).await;
    let inbound = bob.receive(0).await.unwrap();
    assert!(inbound.direct.is_empty() && inbound.items.is_empty() && inbound.dropped == 0);
}

#[tokio::test]
async fn a_relabelled_envelope_cannot_cause_a_group_state_change() {
    let (directory, relay) = start_server().await;
    let mut alice = plain(directory, relay, "+alice").await;
    let mut mallory = plain(directory, relay, "+mallory").await;
    let alice_member = member_of(&alice);
    let (mut bob, _bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let bob_member = bob.member().unwrap();
    let r1 = bob
        .next_roster(vec![alice_member.clone(), bob_member.clone()])
        .unwrap();
    let control = GroupPayload::Roster(r1).encode().unwrap();

    // A genuine control from the authority, labelled as a direct message: the
    // label only chose the parser, so it reaches the application as a direct
    // message and changes no group state.
    alice
        .send_as(bob.address(), &control, Kind::Dm)
        .await
        .unwrap();
    let inbound = bob.receive(0).await.unwrap();
    assert!(inbound.items.is_empty());
    assert_eq!(inbound.direct.len(), 1);
    assert_eq!(bob.roster().unwrap().revision, 0);

    // A direct message labelled group reaches the group parser, fails its own
    // canonical decoding and is refused: it is consumed, and it changes nothing.
    alice
        .send_as(bob.address(), b"hello, a plain direct message", Kind::Group)
        .await
        .unwrap();
    let inbound = bob.receive(0).await.unwrap();
    assert!(inbound.direct.is_empty());
    assert!(matches!(
        inbound.items.as_slice(),
        [GroupReceipt {
            outcome: GroupOutcome::Refused,
            ..
        }]
    ));
    assert_eq!(bob.roster().unwrap().revision, 0);

    // A well-formed control labelled group from a peer that is not the
    // authority passes the parser and dies at the payload's own authentication.
    mallory
        .send_as(bob.address(), &control, Kind::Group)
        .await
        .unwrap();
    let inbound = bob.receive(0).await.unwrap();
    assert!(matches!(
        inbound.items.as_slice(),
        [GroupReceipt {
            outcome: GroupOutcome::Roster {
                disposition: RosterDisposition::Rejected(RosterRefusal::WrongAuthority),
                ..
            },
            ..
        }]
    ));
    assert_eq!(bob.roster().unwrap().revision, 0);

    // The same bytes from the authority under the group label are accepted:
    // authenticity comes from the pairwise peer and the payload, not the label.
    alice
        .send_as(bob.address(), &control, Kind::Group)
        .await
        .unwrap();
    let inbound = bob.receive(0).await.unwrap();
    assert_eq!(
        sole_roster_disposition(&inbound),
        RosterDisposition::Accepted
    );
    assert_eq!(bob.roster().unwrap().revision, 1);
}

#[tokio::test]
async fn an_authority_invites_admits_and_revokes_through_the_coordinator() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let bob_store = SharedStore::default();
    let mut bob = coordinator(directory, relay, "+bob", &bob_store).await;
    let carol_store = SharedStore::default();
    let mut carol = coordinator(directory, relay, "+carol", &carol_store).await;
    bob.await_group(gid(), alice_member.clone()).unwrap();
    carol.await_group(gid(), alice_member.clone()).unwrap();
    let (bob_member, carol_member) = (bob.member().unwrap(), carol.member().unwrap());
    let (bob_route, carol_route) = (route(&bob), route(&carol));
    let bob_invitation = InvitationId::new([1; 16]);
    let carol_invitation = InvitationId::new([2; 16]);

    alice
        .invite(bob_invitation, &bob_member, &bob_route, 100, 0)
        .await
        .unwrap();
    alice
        .invite(carol_invitation, &carol_member, &carol_route, 100, 0)
        .await
        .unwrap();
    let inbound = bob.receive(1).await.unwrap();
    assert!(matches!(
        inbound.items.as_slice(),
        [GroupReceipt {
            outcome: GroupOutcome::Invitation(_),
            ..
        }]
    ));
    assert_eq!(bob.invitations()[0].status, InvitationStatus::Pending);
    let genesis = genesis_of(&alice_member);
    bob.join_group(genesis, alice_member.clone()).unwrap();
    assert_eq!(
        bob.accept_invitation(bob_invitation, &route(&alice), 1)
            .await
            .unwrap(),
        InvitationStatus::AcceptedPendingAdmission
    );
    let inbound = alice.receive(2).await.unwrap();
    assert!(matches!(
        inbound.items.as_slice(),
        [GroupReceipt {
            outcome: GroupOutcome::InvitationStatus(InvitationStatus::AcceptedPendingAdmission),
            ..
        }]
    ));

    // Admission commits the successor and `admitted` together, and Bob applies it.
    let r1 = alice
        .next_roster(vec![alice_member.clone(), bob_member.clone()])
        .unwrap();
    let install = alice
        .install_roster(
            r1,
            &[(bob_member.clone(), bob_route.clone())],
            Some(Admission {
                id: bob_invitation,
                target: bob_member.clone(),
            }),
            3,
        )
        .await
        .unwrap();
    assert_eq!(install.disposition, RosterDisposition::Accepted);
    assert_eq!(
        alice
            .invitations()
            .iter()
            .find(|invitation| invitation.id == bob_invitation)
            .unwrap()
            .status,
        InvitationStatus::Admitted { revision: 1 }
    );
    let inbound = bob.receive(3).await.unwrap();
    assert_eq!(
        sole_roster_disposition(&inbound),
        RosterDisposition::Accepted
    );

    // Carol's invitation is revoked before admission; she learns it.
    let inbound = carol.receive(1).await.unwrap();
    assert_eq!(inbound.items.len(), 1);
    alice
        .revoke_invitation(carol_invitation, &carol_route, 4)
        .await
        .unwrap();
    let inbound = carol.receive(4).await.unwrap();
    assert!(matches!(
        inbound.items.as_slice(),
        [GroupReceipt {
            outcome: GroupOutcome::InvitationStatus(InvitationStatus::Revoked),
            ..
        }]
    ));
    assert_eq!(carol.invitations()[0].status, InvitationStatus::Revoked);
}

#[tokio::test]
async fn an_invitee_invited_after_the_group_moved_joins_from_the_bootstrap_source_roster() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, _bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let bob_member = bob.member().unwrap();
    let bob_route = route(&bob);
    let carol_store = SharedStore::default();
    let mut carol = coordinator(directory, relay, "+carol", &carol_store).await;
    carol.await_group(gid(), alice_member.clone()).unwrap();
    let (carol_member, carol_route) = (carol.member().unwrap(), route(&carol));

    // Bob is admitted at revision 1, so the group has moved past genesis.
    let r1 = alice
        .next_roster(vec![alice_member.clone(), bob_member.clone()])
        .unwrap();
    alice
        .install_roster(
            r1.clone(),
            &[(bob_member.clone(), bob_route.clone())],
            None,
            0,
        )
        .await
        .unwrap();
    assert_eq!(
        sole_roster_disposition(&bob.receive(0).await.unwrap()),
        RosterDisposition::Accepted
    );

    // Carol is invited at revision 1. Her bootstrap carries that source roster.
    let carol_invitation = InvitationId::new([9; 16]);
    alice
        .invite(carol_invitation, &carol_member, &carol_route, 100, 1)
        .await
        .unwrap();
    let inbound = carol.receive(1).await.unwrap();
    let bootstrap = match inbound.items.as_slice() {
        [
            GroupReceipt {
                outcome: GroupOutcome::Invitation(bootstrap),
                ..
            },
        ] => bootstrap.clone(),
        other => panic!("expected the invitation bootstrap, got {other:?}"),
    };
    assert_eq!(bootstrap.source_roster.revision, 1);

    // She joins at the revision she was invited at; she never saw genesis.
    carol
        .join_group(bootstrap.source_roster.clone(), alice_member.clone())
        .unwrap();
    assert_eq!(carol.roster().unwrap(), &r1);
    assert_eq!(carol.roster_digest(), alice.roster_digest());
    carol
        .accept_invitation(carol_invitation, &route(&alice), 2)
        .await
        .unwrap();
    assert_eq!(alice.receive(2).await.unwrap().items.len(), 1);

    // Alice admits her at revision 2; she observes it from her own view and
    // then receives a group message.
    let r2 = alice
        .next_roster(vec![
            alice_member.clone(),
            bob_member.clone(),
            carol_member.clone(),
        ])
        .unwrap();
    alice
        .install_roster(
            r2,
            &[
                (bob_member.clone(), bob_route.clone()),
                (carol_member.clone(), carol_route.clone()),
            ],
            Some(Admission {
                id: carol_invitation,
                target: carol_member.clone(),
            }),
            3,
        )
        .await
        .unwrap();
    assert_eq!(
        sole_roster_disposition(&carol.receive(3).await.unwrap()),
        RosterDisposition::Accepted
    );
    assert_eq!(carol.roster().unwrap().revision, 2);
    alice
        .send_group(&[(carol_member.clone(), carol_route)], b"welcome".to_vec())
        .await
        .unwrap();
    let inbound = carol.receive(3).await.unwrap();
    assert!(matches!(
        inbound.items.as_slice(),
        [GroupReceipt { outcome: GroupOutcome::Event(event), .. }] if event.payload == b"welcome"
    ));
}

#[tokio::test]
async fn joining_from_a_source_roster_refuses_another_authority_and_a_closed_roster() {
    let (directory, relay) = start_server().await;
    let alice = plain(directory, relay, "+alice").await;
    let alice_member = member_of(&alice);
    let store = SharedStore::default();
    let mut bob = coordinator(directory, relay, "+bob", &store).await;
    let bob_member = bob.member().unwrap();
    let source = |group: GroupId, authority: &Member, members: Vec<Member>| {
        Roster::new(
            group,
            1,
            [7; DIGEST_LEN],
            authority.clone(),
            POLICY_VERSION_V1,
            false,
            members,
        )
        .unwrap()
    };
    let mut both = vec![alice_member.clone(), bob_member.clone()];
    both.sort_by(|left, right| left.identity().cmp(right.identity()));
    // The roster names Alice as its authority but the pinned one is Bob.
    assert!(matches!(
        bob.join_group(
            source(gid(), &alice_member, both.clone()),
            bob_member.clone()
        ),
        Err(GroupError::Policy)
    ));
    // A closed roster admits nobody, so it is no source.
    let closed = Roster::new(
        gid(),
        1,
        [7; DIGEST_LEN],
        alice_member.clone(),
        POLICY_VERSION_V1,
        true,
        both.clone(),
    )
    .unwrap();
    assert!(matches!(
        bob.join_group(closed, alice_member.clone()),
        Err(GroupError::Policy)
    ));
    // The same roster, open, from the pinned authority is accepted.
    bob.join_group(source(gid(), &alice_member, both), alice_member)
        .unwrap();
    assert_eq!(bob.roster().unwrap().revision, 1);
}

#[tokio::test]
async fn next_roster_orders_members_by_the_group_crates_own_rule() {
    let (directory, relay) = start_server().await;
    let store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    // Identities that are prefixes of one another, given in the wrong order:
    // as pairs ("a", [ff]) sorts before ("ab", []); as concatenations it would
    // sort after it.
    let prefixed = Member::new(b"a".to_vec(), vec![0xff]);
    let longer = Member::new(b"ab".to_vec(), vec![]);
    let roster = alice
        .next_roster(vec![longer.clone(), alice_member.clone(), prefixed.clone()])
        .unwrap();
    let position = |member: &Member| roster.members.iter().position(|m| m == member).unwrap();
    assert!(position(&prefixed) < position(&longer));
    let mut expected = roster.members.clone();
    expected.sort_by(Member::canonical_cmp);
    assert_eq!(roster.members, expected);
}

#[tokio::test]
async fn an_authority_grows_a_live_group_from_one_to_eight_members() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let genesis = genesis_of(&alice_member);
    let mut members = Vec::new();
    for n in 1..=7 {
        let store = SharedStore::default();
        let mut member = coordinator(directory, relay, &format!("+m{n}"), &store).await;
        member.await_group(gid(), alice_member.clone()).unwrap();
        members.push(member);
    }
    let bindings: Vec<Member> = members.iter().map(|m| m.member().unwrap()).collect();
    let routes: Vec<(Member, DeviceAddr)> = members
        .iter()
        .zip(&bindings)
        .map(|(member, binding)| (binding.clone(), route(member)))
        .collect();

    // Every future member is invited at genesis, so it observes every successor
    // from the first one on and can be admitted at its own revision.
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
    for (n, member) in members.iter_mut().enumerate() {
        assert_eq!(member.receive(1).await.unwrap().items.len(), 1);
        member
            .join_group(genesis.clone(), alice_member.clone())
            .unwrap();
        member
            .accept_invitation(
                InvitationId::new([n as u8 + 1; 16]),
                &alice_route(&alice),
                1,
            )
            .await
            .unwrap();
    }
    assert_eq!(alice.receive(2).await.unwrap().items.len(), 7);

    // One successor per new member, each sent to all seven invitees: 49 control
    // handoffs after the seven bootstraps, against a lifetime cap of eight.
    let mut delivered = 0;
    for k in 1..=7usize {
        let mut roster_members = vec![alice_member.clone()];
        roster_members.extend(bindings[..k].iter().cloned());
        let successor = alice.next_roster(roster_members).unwrap();
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
        assert_eq!(
            install.disposition,
            RosterDisposition::Accepted,
            "revision {k}"
        );
        assert_eq!(install.delivered.len(), 7, "revision {k}");
        assert!(install.pending.is_empty(), "revision {k}");
        delivered += install.delivered.len();
        for member in &mut members {
            let inbound = member.receive(3).await.unwrap();
            assert_eq!(
                sole_roster_disposition(&inbound),
                RosterDisposition::Accepted
            );
            assert_eq!(member.roster().unwrap().revision, k as u64);
        }
    }
    assert_eq!(delivered, 49);
    assert_eq!(alice.roster().unwrap().revision, 7);
    assert_eq!(alice.roster().unwrap().members.len(), 8);
    let retained = alice.group.as_ref().unwrap().control.len_for_tests();
    assert!(
        retained <= 24,
        "the control outbox keeps at most 24 entries, held {retained}"
    );

    // The eight-member group works: one message reaches every member.
    let sent = alice
        .send_group(&routes, b"to all seven".to_vec())
        .await
        .unwrap();
    assert!(
        sent.recipients
            .iter()
            .all(|progress| progress.disposition == RecipientDisposition::RelayAccepted)
    );
    for member in &mut members {
        let inbound = member.receive(3).await.unwrap();
        assert_eq!(inbound.events()[0].payload, b"to all seven");
    }

    // A ninth member is refused by the roster itself (the profile cap of eight).
    let mut nine = vec![alice_member.clone()];
    nine.extend(bindings.iter().cloned());
    nine.push(Member::new(vec![9; 32], vec![1]));
    assert!(alice.next_roster(nine).is_err());
}

fn alice_route(alice: &GroupClient) -> DeviceAddr {
    alice.address().clone()
}

#[tokio::test]
async fn a_removed_member_restarts_with_its_own_receiver_and_keeps_its_event_ids() {
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
    // Bob receives one application message while he is a member: event 0.
    alice
        .send_group(
            &[(bob_member.clone(), bob_route.clone())],
            b"first".to_vec(),
        )
        .await
        .unwrap();
    let inbound = bob.receive(0).await.unwrap();
    assert_eq!(inbound.events()[0].event_id, 0);

    // Alice removes Bob, and Bob applies it.
    let r2 = alice.next_roster(vec![alice_member.clone()]).unwrap();
    let r2_digest = roster_commitment(&r2.encode().unwrap());
    alice
        .install_roster(r2, &[(bob_member.clone(), bob_route.clone())], None, 0)
        .await
        .unwrap();
    assert_eq!(
        sole_roster_disposition(&bob.receive(0).await.unwrap()),
        RosterDisposition::Accepted
    );
    let removed_state = bob_store.durable().unwrap().application_state;

    // Bob restarts. The group crate restores the receiver of a removed member
    // (0130), so he comes back with his own state and no stand-in: it is the
    // durable bytes, it is not active, and it refuses everything addressed to
    // him as not active.
    drop(bob);
    let mut bob = restart(&bob_config, &bob_store).await;
    bob.join_group(genesis_of(&alice_member), alice_member.clone())
        .unwrap();
    assert_eq!(bob.roster().unwrap().revision, 2);
    let restored = bob.group.as_ref().unwrap().receiver.as_ref().unwrap();
    assert_eq!(restored.status(), tacenta_group::ReceiverStatus::NotMember);
    assert!(
        restored.encode_state().unwrap() == removed_state,
        "the receiver is the durable one, with its event counter, not a stand-in"
    );
    let after_removal = GroupPayload::Application(
        ApplicationContext::new(
            gid(),
            2,
            r2_digest,
            alice_member.clone(),
            bob_member.clone(),
            0,
            b"too late".to_vec(),
        )
        .unwrap(),
    )
    .encode()
    .unwrap();
    alice
        .client
        .send_as(&bob_route, &after_removal, Kind::Group)
        .await
        .unwrap();
    let inbound = bob.receive(0).await.unwrap();
    assert!(matches!(
        inbound.items.as_slice(),
        [GroupReceipt {
            outcome: GroupOutcome::Rejected(ReceiveRefusal::NotActive),
            ..
        }]
    ));

    // Alice readmits him. His next event continues his own counter: 1, not a
    // second event 0 for a different message.
    let r3 = alice
        .next_roster(vec![alice_member.clone(), bob_member.clone()])
        .unwrap();
    alice
        .install_roster(r3, &[(bob_member.clone(), bob_route.clone())], None, 0)
        .await
        .unwrap();
    assert_eq!(
        sole_roster_disposition(&bob.receive(0).await.unwrap()),
        RosterDisposition::Accepted
    );
    alice
        .send_group(&[(bob_member, bob_route)], b"second".to_vec())
        .await
        .unwrap();
    let inbound = bob.receive(0).await.unwrap();
    let events = inbound.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].payload, b"second");
    assert_eq!(events[0].event_id, 1);
}

#[tokio::test]
async fn a_freeze_in_the_middle_of_a_batch_acknowledges_only_the_committed_prefix() {
    let (directory, relay) = start_server().await;
    let mut alice = plain(directory, relay, "+alice").await;
    let bob_config = config(directory, relay, "+bob", 1);
    let bob_store = SharedStore::default();
    let mut bob = coordinator(directory, relay, "+bob", &bob_store).await;
    alice
        .send_as(bob.address(), b"first", Kind::Dm)
        .await
        .unwrap();
    alice
        .send_as(bob.address(), b"second", Kind::Dm)
        .await
        .unwrap();

    // The first item commits; the write of the second is in doubt and lost.
    bob_store.script([CommitOutcome::Committed, CommitOutcome::Unknown], false);
    let inbound = bob.receive(0).await.unwrap();
    assert!(inbound.frozen);
    assert_eq!(inbound.direct.len(), 1);
    assert_eq!(inbound.direct[0].plaintext, b"first");
    drop(bob);

    // The first was acknowledged with its commit; only the second comes again.
    let mut bob = restart(&bob_config, &bob_store).await;
    let inbound = bob.receive(0).await.unwrap();
    assert_eq!(inbound.direct.len(), 1);
    assert_eq!(inbound.direct[0].plaintext, b"second");
    assert_eq!(inbound.dropped, 0);
}

fn staged(
    kind: MessageKind,
    plaintext: Option<Vec<u8>>,
    authenticated_identity: Option<Vec<u8>>,
    effect: CryptoStateEffect,
    provider_state: Vec<u8>,
) -> crate::StagedItem {
    crate::StagedItem {
        from: DeviceAddr::new("+peer", 1),
        peer: Address::new("+peer", 1),
        kind,
        plaintext,
        authenticated_identity,
        effect,
        provider_state,
    }
}

#[tokio::test]
async fn a_terminal_provider_failure_commits_its_state_and_an_unchanged_one_commits_nothing() {
    let (directory, relay) = start_server().await;
    let store = SharedStore::default();
    let mut bob = coordinator(directory, relay, "+bob", &store).await;
    let generation = bob.generation();

    // The provider refused the ciphertext and changed nothing: nothing to keep.
    let mut inbound = Inbound::default();
    bob.commit_item(
        staged(
            MessageKind::Group,
            None,
            None,
            CryptoStateEffect::Unchanged,
            Vec::new(),
        ),
        0,
        &mut inbound,
    )
    .unwrap();
    assert_eq!(inbound.dropped, 1);
    assert_eq!(bob.generation(), generation);

    // It refused the ciphertext and reached a terminal state that must be kept.
    bob.commit_item(
        staged(
            MessageKind::Group,
            None,
            None,
            CryptoStateEffect::Terminal,
            vec![7, 7, 7],
        ),
        0,
        &mut inbound,
    )
    .unwrap();
    assert_eq!(inbound.dropped, 2);
    let durable = store.durable().unwrap();
    assert_eq!(durable.generation, generation + 1);
    assert_eq!(durable.provider_state, vec![7, 7, 7]);
    assert_eq!(durable.inbox.len(), 1);
    assert_eq!(&durable.inbox[0][..5], b"TCGM\x02");
    assert_eq!(durable.inbox[0].len(), 41, "no plaintext is kept");
}

#[tokio::test]
async fn a_group_item_without_an_authenticated_peer_is_refused_not_attributed() {
    let (directory, relay) = start_server().await;
    let alice = plain(directory, relay, "+alice").await;
    let alice_member = member_of(&alice);
    let (mut bob, store) = joined(directory, relay, "+bob", &alice_member).await;
    let bob_member = bob.member().unwrap();
    let r1 = bob
        .next_roster(vec![alice_member.clone(), bob_member])
        .unwrap();
    let control = GroupPayload::Roster(r1).encode().unwrap();
    let mut inbound = Inbound::default();
    bob.commit_item(
        staged(
            MessageKind::Group,
            Some(control),
            None,
            CryptoStateEffect::Advanced,
            vec![5],
        ),
        0,
        &mut inbound,
    )
    .unwrap();
    assert!(matches!(
        inbound.items.as_slice(),
        [GroupReceipt {
            outcome: GroupOutcome::Refused,
            ..
        }]
    ));
    assert_eq!(bob.roster().unwrap().revision, 0);
    assert_eq!(store.durable().unwrap().provider_state, vec![5]);
}

#[tokio::test]
async fn a_bootstrap_from_a_peer_that_is_not_the_pinned_authority_is_refused() {
    let (directory, relay) = start_server().await;
    let alice = plain(directory, relay, "+alice").await;
    let mut mallory = plain(directory, relay, "+mallory").await;
    let store = SharedStore::default();
    let mut bob = coordinator(directory, relay, "+bob", &store).await;
    bob.await_group(gid(), member_of(&alice)).unwrap();
    let bob_member = bob.member().unwrap();

    // A bootstrap that is well formed and names Mallory as its own authority.
    let mallory_member = member_of(&mallory);
    let genesis = genesis_of(&mallory_member);
    let digest = roster_commitment(&genesis.encode().unwrap());
    let invitation = Invitation::new(
        InvitationId::new([9; 16]),
        gid(),
        bob_member,
        0,
        digest,
        POLICY_VERSION_V1,
        100,
    )
    .unwrap();
    let bootstrap =
        GroupPayload::InvitationBootstrap(InvitationBootstrap::new(invitation, genesis).unwrap())
            .encode()
            .unwrap();
    mallory
        .send_as(bob.address(), &bootstrap, Kind::Group)
        .await
        .unwrap();
    let inbound = bob.receive(1).await.unwrap();
    assert!(matches!(
        inbound.items.as_slice(),
        [GroupReceipt {
            outcome: GroupOutcome::Refused,
            ..
        }]
    ));
    assert!(bob.invitations().is_empty());
}

#[tokio::test]
async fn an_installed_roster_is_only_fanned_out_when_it_is_installed_again() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, _) = joined(directory, relay, "+bob", &alice_member).await;
    let (mut carol, _) = joined(directory, relay, "+carol", &alice_member).await;
    let (bob_member, carol_member) = (bob.member().unwrap(), carol.member().unwrap());
    let r1 = alice
        .next_roster(vec![
            alice_member.clone(),
            bob_member.clone(),
            carol_member.clone(),
        ])
        .unwrap();
    let first = alice
        .install_roster(r1.clone(), &[(bob_member.clone(), route(&bob))], None, 0)
        .await
        .unwrap();
    assert_eq!(first.disposition, RosterDisposition::Accepted);

    // The same successor again reaches a recipient that was left out; it is
    // not a second local transition.
    let again = alice
        .install_roster(r1, &[(carol_member.clone(), route(&carol))], None, 0)
        .await
        .unwrap();
    assert_eq!(again.disposition, RosterDisposition::Duplicate);
    assert_eq!(again.delivered, vec![carol_member]);
    assert_eq!(
        sole_roster_disposition(&bob.receive(0).await.unwrap()),
        RosterDisposition::Accepted
    );
    assert_eq!(
        sole_roster_disposition(&carol.receive(0).await.unwrap()),
        RosterDisposition::Accepted
    );
}

#[tokio::test]
async fn a_freeze_while_preparing_a_group_send_is_reported_not_swallowed() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (bob, _) = joined(directory, relay, "+bob", &alice_member).await;
    let bob_member = bob.member().unwrap();
    let r1 = alice
        .next_roster(vec![alice_member.clone(), bob_member.clone()])
        .unwrap();
    alice
        .install_roster(r1, &[(bob_member.clone(), route(&bob))], None, 0)
        .await
        .unwrap();

    // The intent commits; the recipient's preparation is in doubt.
    alice_store.script([CommitOutcome::Committed, CommitOutcome::Unknown], false);
    let result = alice
        .send_group(&[(bob_member.clone(), route(&bob))], b"doubtful".to_vec())
        .await;
    assert!(matches!(result, Err(GroupError::Frozen)));
    assert!(alice.is_frozen());
    assert!(matches!(
        alice
            .send_group(&[(bob_member, route(&bob))], b"later".to_vec())
            .await,
        Err(GroupError::Frozen)
    ));
}

#[tokio::test]
async fn a_snapshot_of_another_identity_is_not_adopted() {
    let (directory, relay) = start_server().await;
    let store = SharedStore::default();
    let alice = coordinator(directory, relay, "+alice", &store).await;
    drop(alice);
    let result = GroupClient::open(plain(directory, relay, "+carol").await, store.clone()).await;
    assert!(matches!(result.err(), Some(GroupError::Recovery)));
}

#[tokio::test]
async fn recovery_forgets_the_sessions_of_the_state_it_discards() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    let mut bob = plain(directory, relay, "+bob").await;
    let bob_route = bob.address().clone();

    // The first send opens a session and encrypts, and the commit fails: the
    // session exists only in the memory that recovery is about to discard.
    alice_store.script([CommitOutcome::Failed], false);
    assert!(matches!(
        alice.send_direct(&bob_route, b"one").await,
        Err(GroupError::Frozen)
    ));
    assert!(alice.client.has_open_session(&bob_route));
    alice.recover().await.unwrap();
    assert!(
        !alice.client.has_open_session(&bob_route),
        "a session the durable state does not hold is still recorded"
    );

    // So the next send opens a new session rather than encrypting for a
    // session that is gone.
    alice.send_direct(&bob_route, b"two").await.unwrap();
    let received = bob.receive().await.unwrap();
    assert_eq!(received.len(), 1);
    assert_eq!(received[0].plaintext, b"two");
}

#[tokio::test]
async fn receive_next_waits_for_mail_and_returns_it() {
    let (directory, relay) = start_server().await;
    let mut alice = plain(directory, relay, "+alice").await;
    let store = SharedStore::default();
    let mut bob = coordinator(directory, relay, "+bob", &store).await;
    let bob_route = bob.address().clone();
    let (sent, received) = tokio::join!(
        async {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            alice.send_as(&bob_route, b"late", Kind::Dm).await
        },
        bob.receive_next(0)
    );
    sent.unwrap();
    let inbound = received.unwrap();
    assert_eq!(inbound.direct.len(), 1);
    assert_eq!(inbound.direct[0].plaintext, b"late");
}

#[tokio::test]
async fn a_control_committed_before_a_freeze_is_handed_off_after_recovery() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, _) = joined(directory, relay, "+bob", &alice_member).await;
    let bob_member = bob.member().unwrap();
    let routes = vec![(bob_member.clone(), route(&bob))];
    let r1 = alice
        .next_roster(vec![alice_member.clone(), bob_member.clone()])
        .unwrap();

    // The installation and the exact control commit; the reservation of the
    // handoff is in doubt and lost.
    alice_store.script([CommitOutcome::Committed, CommitOutcome::Unknown], false);
    assert!(matches!(
        alice.install_roster(r1, &routes, None, 0).await,
        Err(GroupError::Frozen)
    ));
    assert!(bob.receive(0).await.unwrap().items.is_empty());

    alice.recover().await.unwrap();
    assert_eq!(alice.roster().unwrap().revision, 1);
    assert_eq!(alice.dispatch_pending_controls(&routes).await.unwrap(), 1);
    assert_eq!(
        sole_roster_disposition(&bob.receive(0).await.unwrap()),
        RosterDisposition::Accepted
    );
    // Nothing is left to send.
    assert_eq!(alice.dispatch_pending_controls(&routes).await.unwrap(), 0);
}

#[tokio::test]
async fn a_group_send_committed_before_a_freeze_is_handed_off_after_recovery() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, _) = joined(directory, relay, "+bob", &alice_member).await;
    let bob_member = bob.member().unwrap();
    let routes = vec![(bob_member.clone(), route(&bob))];
    let r1 = alice
        .next_roster(vec![alice_member.clone(), bob_member.clone()])
        .unwrap();
    alice.install_roster(r1, &routes, None, 0).await.unwrap();
    assert_eq!(
        sole_roster_disposition(&bob.receive(0).await.unwrap()),
        RosterDisposition::Accepted
    );

    // The intent and the exact ciphertext commit; the reservation is in doubt.
    alice_store.script(
        [
            CommitOutcome::Committed,
            CommitOutcome::Committed,
            CommitOutcome::Unknown,
        ],
        false,
    );
    assert!(matches!(
        alice.send_group(&routes, b"resumed".to_vec()).await,
        Err(GroupError::Frozen)
    ));
    assert!(bob.receive(0).await.unwrap().events().is_empty());

    alice.recover().await.unwrap();
    assert_eq!(
        alice.dispatch_pending_group_sends(&routes).await.unwrap(),
        1
    );
    let inbound = bob.receive(0).await.unwrap();
    assert_eq!(inbound.events()[0].payload, b"resumed");
    assert_eq!(
        alice.dispatch_pending_group_sends(&routes).await.unwrap(),
        0
    );
}
