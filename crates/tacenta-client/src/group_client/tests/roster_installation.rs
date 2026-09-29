//! Installing a roster through `GroupClient` (`crates/tacenta-client/src/group_client.rs`): a
//! conflicting roster at the installed revision is refused and not fanned out, and a roster reports
//! the deferred application messages it unlocks.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made. They run the live coordinator against the in-process directory and relay.
//!
//! - M023 (`group_client.rs:915`): `install_roster` treats a different roster at the installed
//!   revision as already installed.
//! - M033 (`group_client.rs:743`): `route` consumes the event IDs of the messages an accepted
//!   roster unlocks but does not report them.
//!
//! The ids (`M###`, `D##`) are those of the single-change mutation run against 97689a0; the
//! `file:line` in each test's doc comment is the change site at that commit.

use super::*;

/// M023 (`group_client.rs:915`): in `install_roster`, `let mut installed = view.roster() ==
/// &successor;` becomes `view.roster().revision == successor.revision`, so a different roster at
/// the installed revision is treated as "already installed": the installed roster is fanned out and
/// the call reports success.
#[tokio::test]
async fn m023_a_conflicting_roster_at_the_installed_revision_is_refused_not_fanned_out() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, _) = joined(directory, relay, "+bob", &alice_member).await;
    let (carol, _) = joined(directory, relay, "+carol", &alice_member).await;
    let (bob_member, carol_member) = (bob.member().unwrap(), carol.member().unwrap());

    let r1 = alice
        .next_roster(vec![alice_member.clone(), bob_member.clone()])
        .unwrap();
    alice
        .install_roster(r1.clone(), &[(bob_member.clone(), route(&bob))], None, 0)
        .await
        .unwrap();
    assert_eq!(
        sole_roster_disposition(&bob.receive(0).await.unwrap()),
        RosterDisposition::Accepted
    );

    // Another roster for the same revision and predecessor, with other members.
    let mut members = vec![alice_member.clone(), carol_member.clone()];
    members.sort_by(Member::canonical_cmp);
    let conflicting = Roster::new(
        gid(),
        r1.revision,
        r1.predecessor_digest,
        alice_member.clone(),
        POLICY_VERSION_V1,
        false,
        members,
    )
    .unwrap();
    assert_ne!(conflicting, r1);

    let result = alice
        .install_roster(conflicting, &[(bob_member.clone(), route(&bob))], None, 0)
        .await;
    assert!(
        matches!(result, Err(GroupError::Policy)),
        "a conflicting roster must be refused, got {result:?}"
    );
    assert_eq!(alice.roster().unwrap(), &r1);
    // Nothing was sent to Bob.
    assert!(bob.receive(0).await.unwrap().items.is_empty());
}

/// M033 (`group_client.rs:743`): in `route`, the Roster arm's
/// `events.push(GroupEvent::new(event_id, &item.context));` becomes `let _ = event_id;`, so the
/// application messages an accepted roster unlocks from the future queue are committed (their event
/// IDs consumed) but never reported: `Inbound::events()` loses them.
#[tokio::test]
async fn m033_a_roster_reports_the_deferred_message_it_unlocks() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, _) = joined(directory, relay, "+bob", &alice_member).await;
    let (carol, _) = joined(directory, relay, "+carol", &alice_member).await;
    let (bob_member, carol_member) = (bob.member().unwrap(), carol.member().unwrap());
    let (bob_route, carol_route) = (route(&bob), route(&carol));

    // Revision 1: Alice and Bob. Bob accepts it.
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

    // Revision 2 adds Carol; only Carol is told for now.
    let r2 = alice
        .next_roster(vec![
            alice_member.clone(),
            bob_member.clone(),
            carol_member.clone(),
        ])
        .unwrap();
    alice
        .install_roster(
            r2.clone(),
            &[(carol_member.clone(), carol_route.clone())],
            None,
            0,
        )
        .await
        .unwrap();
    // A revision-2 message reaches Bob, who is still at revision 1: deferred.
    alice
        .send_group(
            &[(bob_member.clone(), bob_route.clone())],
            b"future".to_vec(),
        )
        .await
        .unwrap();
    let inbound = bob.receive(0).await.unwrap();
    assert!(matches!(
        inbound.items.as_slice(),
        [GroupReceipt {
            outcome: GroupOutcome::Deferred,
            ..
        }]
    ));

    // Now Bob learns revision 2: the deferred message is accepted and reported.
    alice
        .install_roster(r2, &[(bob_member.clone(), bob_route)], None, 0)
        .await
        .unwrap();
    let inbound = bob.receive(0).await.unwrap();
    let events = inbound.events();
    assert_eq!(events.len(), 1, "{inbound:?}");
    assert_eq!(events[0].payload, b"future");
}
