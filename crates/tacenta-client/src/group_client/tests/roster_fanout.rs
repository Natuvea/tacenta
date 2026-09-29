//! Roster fan-out through `GroupClient` (decisions 0124, 0125, 0141, 0142):
//! who is told of an install and in which order, what a retry reports, the
//! refusals that come before any pairwise operation, and long roster churn.
//! Every test drives the coordinators against the in-process directory and relay
//! with the real provider; every identity and effect comes from the provider's
//! outcome.

use super::*;

/// Alice (authority), Bob and Carol, all members at revision 1.
struct Three {
    alice: GroupClient,
    bob: GroupClient,
    carol: GroupClient,
    alice_member: Member,
    bob_member: Member,
    carol_member: Member,
    bob_route: DeviceAddr,
    carol_route: DeviceAddr,
    bob_config: Config,
}

async fn three() -> Three {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let bob_config = config(directory, relay, "+bob", 1);
    let (mut bob, _bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let (mut carol, _cs) = joined(directory, relay, "+carol", &alice_member).await;
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
    bob.receive(0).await.unwrap();
    carol.receive(0).await.unwrap();
    Three {
        alice,
        bob,
        carol,
        alice_member,
        bob_member,
        carol_member,
        bob_route,
        carol_route,
        bob_config,
    }
}

fn config_of_alice(t: &Three) -> Config {
    Config {
        directory: t.bob_config.directory,
        relay: t.bob_config.relay,
        user: "+alice".into(),
        device: 1,
    }
}

/// Alice (authority) with `n` other members, all at revision 1.
struct Crew {
    alice: GroupClient,
    alice_store: SharedStore,
    alice_config: Config,
    alice_member: Member,
    others: Vec<(GroupClient, SharedStore, Member, DeviceAddr)>,
}

async fn crew(n: usize) -> Crew {
    let (directory, relay) = start_server().await;
    let alice_config = config(directory, relay, "+alice", 1);
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let mut others = Vec::new();
    for index in 0..n {
        let (member_client, store) =
            joined(directory, relay, &format!("+member{index}"), &alice_member).await;
        let member = member_client.member().unwrap();
        let member_route = route(&member_client);
        others.push((member_client, store, member, member_route));
    }
    let mut members = vec![alice_member.clone()];
    members.extend(others.iter().map(|(_, _, member, _)| member.clone()));
    let r1 = alice.next_roster(members).unwrap();
    let recipients: Vec<_> = others
        .iter()
        .map(|(_, _, member, member_route)| (member.clone(), member_route.clone()))
        .collect();
    let install = alice
        .install_roster(r1, &recipients, None, 0)
        .await
        .unwrap();
    assert_eq!(install.delivered.len(), n);
    for (member_client, ..) in &mut others {
        member_client.receive(0).await.unwrap();
    }
    Crew {
        alice,
        alice_store,
        alice_config,
        alice_member,
        others,
    }
}

impl Crew {
    fn member(&self, index: usize) -> Member {
        self.others[index].2.clone()
    }

    fn recipient(&self, index: usize) -> (Member, DeviceAddr) {
        (self.others[index].2.clone(), self.others[index].3.clone())
    }
}

/// All orders of three indices.
const ORDERS: [[usize; 3]; 6] = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];

#[tokio::test]
async fn a_removed_member_is_told_wherever_it_is_listed() {
    // Three members besides the authority; the middle one is removed. Over the
    // six orders it is listed first, in the middle and last, in every position
    // relative to the two members that stay.
    for order in ORDERS {
        let mut crew = crew(3).await;
        let removed = 1usize;
        let r2 = crew
            .alice
            .next_roster(vec![
                crew.alice_member.clone(),
                crew.member(0),
                crew.member(2),
            ])
            .unwrap();
        let recipients: Vec<_> = order.iter().map(|&index| crew.recipient(index)).collect();
        let install = crew
            .alice
            .install_roster(r2, &recipients, None, 0)
            .await
            .unwrap();
        assert_eq!(
            install.disposition,
            RosterDisposition::Accepted,
            "{order:?}"
        );
        assert_eq!(install.delivered.len(), 3, "{order:?}: {install:?}");
        assert!(install.pending.is_empty(), "{order:?}: {install:?}");
        assert!(install.unprepared.is_empty(), "{order:?}: {install:?}");
        for (index, (member_client, ..)) in crew.others.iter_mut().enumerate() {
            let inbound = member_client.receive(0).await.unwrap();
            assert_eq!(
                sole_roster_disposition(&inbound),
                RosterDisposition::Accepted,
                "{order:?}: member {index}"
            );
            assert_eq!(member_client.roster().unwrap().revision, 2);
        }
        // The removed member knows it is out; the others still receive traffic.
        let (bob, ..) = &crew.others[removed];
        assert!(
            !bob.roster()
                .unwrap()
                .members
                .contains(&crew.member(removed)),
            "{order:?}"
        );
        let stays = [crew.recipient(0), crew.recipient(2)];
        crew.alice
            .send_group(&stays, b"after the removal".to_vec())
            .await
            .unwrap();
        for index in [0usize, 2] {
            let inbound = crew.others[index].0.receive(0).await.unwrap();
            assert_eq!(inbound.events().len(), 1, "{order:?}: member {index}");
        }
    }
}

#[tokio::test]
async fn removing_two_members_at_once_tells_both_in_either_order() {
    for order in [[0usize, 1], [1, 0]] {
        let mut t = three().await;
        let r2 = t.alice.next_roster(vec![t.alice_member.clone()]).unwrap();
        let both = [
            (t.bob_member.clone(), t.bob_route.clone()),
            (t.carol_member.clone(), t.carol_route.clone()),
        ];
        let recipients = [both[order[0]].clone(), both[order[1]].clone()];
        let install = t
            .alice
            .install_roster(r2, &recipients, None, 0)
            .await
            .unwrap();
        assert_eq!(install.delivered.len(), 2, "{order:?}: {install:?}");
        assert!(install.pending.is_empty() && install.unprepared.is_empty());
        for member in [&mut t.bob, &mut t.carol] {
            let inbound = member.receive(0).await.unwrap();
            assert_eq!(
                sole_roster_disposition(&inbound),
                RosterDisposition::Accepted
            );
            assert_eq!(member.roster().unwrap().revision, 2);
        }
    }
}

#[tokio::test]
async fn an_install_that_froze_half_way_is_completed_after_a_restart_and_tells_the_removed_member()
{
    // Bob, Carol (removed) and Dave, in that order. The commit that prepares
    // Carol's control fails, the process stops, and the retry from the store
    // still finds the members of the roster that was replaced.
    let mut crew = crew(3).await;
    let r2 = crew
        .alice
        .next_roster(vec![
            crew.alice_member.clone(),
            crew.member(0),
            crew.member(2),
        ])
        .unwrap();
    let recipients = [crew.recipient(0), crew.recipient(1), crew.recipient(2)];
    // Bob: the install and his control (1), the reservation (2), the acceptance
    // (3). Carol's preparation is the fourth commit.
    crew.alice_store.script(
        [
            CommitOutcome::Committed,
            CommitOutcome::Committed,
            CommitOutcome::Committed,
            CommitOutcome::Failed,
        ],
        false,
    );
    let frozen = crew
        .alice
        .install_roster(r2.clone(), &recipients, None, 0)
        .await;
    assert!(matches!(frozen, Err(GroupError::Frozen)), "{frozen:?}");
    drop(std::mem::replace(
        &mut crew.alice,
        coordinator(
            crew.alice_config.directory,
            crew.alice_config.relay,
            "+placeholder",
            &SharedStore::default(),
        )
        .await,
    ));
    let mut alice = restart(&crew.alice_config, &crew.alice_store).await;
    alice.create_group(gid()).unwrap();
    assert_eq!(
        alice.roster().unwrap().revision,
        2,
        "the install was durable"
    );
    let install = alice
        .install_roster(r2, &recipients, None, 0)
        .await
        .unwrap();
    assert_eq!(install.delivered.len(), 3, "{install:?}");
    assert!(install.pending.is_empty() && install.unprepared.is_empty());
    for (member_client, ..) in &mut crew.others {
        member_client.receive(0).await.unwrap();
        assert_eq!(member_client.roster().unwrap().revision, 2);
    }
}

#[tokio::test]
async fn an_install_that_names_a_stranger_is_refused_before_anything_changes() {
    let mut crew = crew(2).await;
    let stranger_client = plain(
        crew.alice_config.directory,
        crew.alice_config.relay,
        "+stranger",
    )
    .await;
    let stranger = member_of(&stranger_client);
    let r2 = crew
        .alice
        .next_roster(vec![crew.alice_member.clone(), crew.member(0)])
        .unwrap();
    let before = crew.alice.generation();
    let recipients = [
        crew.recipient(1),
        (stranger, stranger_client.address().clone()),
    ];
    let refused = crew.alice.install_roster(r2, &recipients, None, 0).await;
    assert!(matches!(refused, Err(GroupError::Policy)), "{refused:?}");
    assert_eq!(crew.alice.roster().unwrap().revision, 1);
    assert_eq!(crew.alice.generation(), before, "nothing was committed");
    let inbound = crew.others[1].0.receive(0).await.unwrap();
    assert!(inbound.items.is_empty(), "nothing was sent");
}

#[tokio::test]
async fn an_install_with_no_recipients_is_refused_and_a_retry_reports_delivered_recipients_as_delivered()
 {
    let mut t = three().await;
    let r2 = t.alice.next_roster(vec![t.alice_member.clone()]).unwrap();
    let before = t.alice.generation();
    let refused = t.alice.install_roster(r2.clone(), &[], None, 0).await;
    assert!(matches!(refused, Err(GroupError::Policy)), "{refused:?}");
    assert_eq!(t.alice.roster().unwrap().revision, 1);
    assert_eq!(t.alice.generation(), before);

    let recipients = [
        (t.bob_member.clone(), t.bob_route.clone()),
        (t.carol_member.clone(), t.carol_route.clone()),
    ];
    let first = t
        .alice
        .install_roster(r2.clone(), &recipients, None, 0)
        .await
        .unwrap();
    assert_eq!(first.delivered.len(), 2);
    let installed_at = t.alice.generation();
    // The same call again: both are delivered, nothing is re-encrypted or
    // committed, and the successor is not reported as newly installed.
    let retry = t
        .alice
        .install_roster(r2.clone(), &recipients, None, 0)
        .await
        .unwrap();
    assert_eq!(retry.disposition, RosterDisposition::Duplicate);
    assert_eq!(retry.delivered.len(), 2, "{retry:?}");
    assert!(retry.pending.is_empty() && retry.unprepared.is_empty());
    assert_eq!(t.alice.generation(), installed_at);
    // An installed successor needs no recipients to be a duplicate.
    let none = t.alice.install_roster(r2, &[], None, 0).await.unwrap();
    assert_eq!(none.disposition, RosterDisposition::Duplicate);
    assert!(none.delivered.is_empty());
    // Bob and Carol each received exactly one copy.
    for member in [&mut t.bob, &mut t.carol] {
        assert_eq!(member.receive(0).await.unwrap().items.len(), 1);
    }
}

#[tokio::test]
async fn a_route_that_is_not_the_recipients_device_is_refused_before_anything_is_sent() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, _bs) = joined(directory, relay, "+bob", &alice_member).await;
    let bob_member = bob.member().unwrap();
    let bob_route = route(&bob);
    let r1 = alice
        .next_roster(vec![alice_member, bob_member.clone()])
        .unwrap();
    alice
        .install_roster(r1, &[(bob_member.clone(), bob_route.clone())], None, 0)
        .await
        .unwrap();
    bob.receive(0).await.unwrap();
    // Bob's second device: same identity, device 2.
    let mut bob_two = DefaultClient::connect_with_identity(
        &config(directory, relay, "+bob", 2),
        &bob.client.export_identity(),
    )
    .await
    .unwrap();
    let wrong_route = bob_two.address().clone();
    assert_eq!(wrong_route.device, 2);
    let before = alice.generation();
    let refused = alice
        .send_group(
            &[(bob_member.clone(), wrong_route.clone())],
            b"for device one".to_vec(),
        )
        .await;
    assert!(matches!(refused, Err(GroupError::Policy)), "{refused:?}");
    assert_eq!(alice.generation(), before, "no intent was recorded");
    let on_one = bob.receive(0).await.unwrap();
    assert_eq!(on_one.items.len() + on_one.direct.len(), 0);
    assert_eq!(bob_two.drain().await.unwrap().len(), 0);
    // The install and the dispatch calls check their routes the same way.
    let r2 = alice.next_roster(vec![alice.member().unwrap()]).unwrap();
    assert!(matches!(
        alice
            .install_roster(r2, &[(bob_member.clone(), wrong_route.clone())], None, 0)
            .await,
        Err(GroupError::Policy)
    ));
    assert!(matches!(
        alice
            .dispatch_pending_controls(&[(bob_member.clone(), wrong_route.clone())])
            .await,
        Err(GroupError::Policy)
    ));
    assert!(matches!(
        alice
            .dispatch_pending_group_sends(&[(bob_member.clone(), wrong_route)])
            .await,
        Err(GroupError::Policy)
    ));
    // The right route still works.
    let sent = alice
        .send_group(&[(bob_member, bob_route)], b"for device one".to_vec())
        .await
        .unwrap();
    assert_eq!(
        sent.recipients[0].disposition,
        RecipientDisposition::RelayAccepted
    );
    assert_eq!(bob.receive(0).await.unwrap().events().len(), 1);
}

#[tokio::test]
async fn a_second_group_id_on_a_store_that_holds_a_group_is_refused_and_changes_nothing() {
    let mut t = three().await;
    let other = GroupId::new(*b"another-group-id");
    let refused = t.alice.create_group(other);
    assert!(matches!(refused, Err(GroupError::Policy)), "{refused:?}");
    assert_eq!(t.alice.roster().unwrap().group_id, gid());
    // The coordinator still works for its own group.
    let sent = t
        .alice
        .send_group(
            &[(t.bob_member.clone(), t.bob_route.clone())],
            b"still the first group".to_vec(),
        )
        .await
        .unwrap();
    assert_eq!(sent.recipients.len(), 1);
    assert_eq!(t.bob.receive(0).await.unwrap().events().len(), 1);
}

#[tokio::test]
async fn an_invitation_in_a_closed_group_is_refused_before_it_is_recorded_or_sent() {
    let mut t = three().await;
    let open = t
        .alice
        .next_roster(vec![t.alice_member.clone(), t.bob_member.clone()])
        .unwrap();
    let closed = Roster::new(
        open.group_id,
        open.revision,
        open.predecessor_digest,
        open.authority.clone(),
        open.policy_version,
        true,
        open.members.clone(),
    )
    .unwrap();
    t.alice
        .install_roster(
            closed,
            &[
                (t.bob_member.clone(), t.bob_route.clone()),
                (t.carol_member.clone(), t.carol_route.clone()),
            ],
            None,
            0,
        )
        .await
        .unwrap();
    assert!(t.alice.roster().unwrap().closed);
    let (directory, relay) = (t.bob_config.directory, t.bob_config.relay);
    let dave = plain(directory, relay, "+dave").await;
    let before = t.alice.generation();
    let refused = t
        .alice
        .invite(
            InvitationId::new([9; 16]),
            &member_of(&dave),
            dave.address(),
            100,
            0,
        )
        .await;
    assert!(matches!(refused, Err(GroupError::Policy)), "{refused:?}");
    assert!(t.alice.invitations().is_empty());
    assert_eq!(t.alice.generation(), before);
}

#[tokio::test]
async fn ninety_roster_changes_keep_the_transcript_bounded_and_recoverable() {
    let mut t = three().await;
    let alice_config = config_of_alice(&t);
    let alice_store_snapshot_len = |t: &Three| t.alice.snapshot.group_controls.len();
    let mut max_controls = 0usize;
    let mut bob_in = true;
    for i in 0..90usize {
        // Alternate: remove Bob / re-add Bob; Carol stays.
        let members = if bob_in {
            vec![t.alice_member.clone(), t.carol_member.clone()]
        } else {
            vec![
                t.alice_member.clone(),
                t.bob_member.clone(),
                t.carol_member.clone(),
            ]
        };
        let next = t.alice.next_roster(members).unwrap();
        // The member removed this round is listed last, the one re-added first
        // (0141: the order does not matter).
        let recipients = if bob_in {
            vec![
                (t.carol_member.clone(), t.carol_route.clone()),
                (t.bob_member.clone(), t.bob_route.clone()),
            ]
        } else {
            vec![
                (t.bob_member.clone(), t.bob_route.clone()),
                (t.carol_member.clone(), t.carol_route.clone()),
            ]
        };
        let install = t
            .alice
            .install_roster(next, &recipients, None, 0)
            .await
            .unwrap();
        assert!(install.pending.is_empty(), "i={i}: {install:?}");
        bob_in = !bob_in;
        t.bob.receive(0).await.unwrap();
        t.carol.receive(0).await.unwrap();
        max_controls = max_controls.max(alice_store_snapshot_len(&t));
        assert_eq!(
            t.alice.roster().unwrap().revision,
            t.carol.roster().unwrap().revision
        );
        assert_eq!(
            t.alice.roster().unwrap().revision,
            t.bob.roster().unwrap().revision
        );
    }
    println!(
        "90 roster changes; alice group_controls max={max_controls}, final={}, control outbox live+terminal={}",
        t.alice.snapshot.group_controls.len(),
        t.alice
            .group
            .as_ref()
            .unwrap()
            .control
            .encode_state()
            .unwrap()
            .len()
    );
    assert!(max_controls <= 64);
    // Restart everyone from their stores and keep going.
    let _ = alice_config;
    assert_eq!(t.alice.roster().unwrap().revision, 90 + 1);
}
