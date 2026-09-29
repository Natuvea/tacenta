//! What a registered peer that is not in the group can do to a member's deferral slots with the
//! application contexts it is allowed to send (decisions 0142, 0146). Every test drives real
//! coordinators against the in-process directory and relay with the real provider; the stranger is a
//! plain client with its own account that knows the group ID and a member's route.

use super::*;
use tacenta_group::ApplicationContext;

/// Alice (authority), Bob (a member) and Carol, who is admitted at revision 2 and told before Bob.
struct Admission {
    alice: GroupClient,
    bob: GroupClient,
    carol: GroupClient,
    r2: Roster,
    bob_member: Member,
    bob_route: DeviceAddr,
    directory: SocketAddr,
    relay: SocketAddr,
}

async fn carol_is_admitted_and_bob_is_not_told_yet() -> Admission {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, _bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let (bob_member, bob_route) = (bob.member().unwrap(), route(&bob));
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
    bob.receive(0).await.unwrap();
    let carol_store = SharedStore::default();
    let mut carol = coordinator(directory, relay, "+carol", &carol_store).await;
    carol.join_group(r1, alice_member.clone()).unwrap();
    let carol_member = carol.member().unwrap();
    let carol_route = route(&carol);
    let r2 = alice
        .next_roster(vec![alice_member, bob_member.clone(), carol_member.clone()])
        .unwrap();
    alice
        .install_roster(r2.clone(), &[(carol_member, carol_route)], None, 0)
        .await
        .unwrap();
    carol.receive(0).await.unwrap();
    Admission {
        alice,
        bob,
        carol,
        r2,
        bob_member,
        bob_route,
        directory,
        relay,
    }
}

/// A context for revision 2 from `sender`, addressed to Bob, that no roster admits `sender` to.
fn stranger_context(sender: &Member, bob: &Member, sequence: u64) -> Vec<u8> {
    GroupPayload::Application(
        ApplicationContext::new(
            gid(),
            2,
            [5; DIGEST_LEN],
            sender.clone(),
            bob.clone(),
            sequence,
            b"stranger".to_vec(),
        )
        .unwrap(),
    )
    .encode()
    .unwrap()
}

/// Carol writes to Bob before Bob has the roster that admits her; then the roster arrives. What Bob
/// shows for Carol's message, and every outcome he saw on the way.
async fn carol_writes_first(a: &mut Admission) -> (Vec<Vec<u8>>, Vec<GroupOutcome>) {
    a.carol
        .send_group(
            &[(a.bob_member.clone(), a.bob_route.clone())],
            b"carol says hi".to_vec(),
        )
        .await
        .unwrap();
    let mut inbounds = vec![a.bob.receive(0).await.unwrap()];
    a.alice
        .install_roster(
            a.r2.clone(),
            &[(a.bob_member.clone(), a.bob_route.clone())],
            None,
            0,
        )
        .await
        .unwrap();
    inbounds.push(a.bob.receive(0).await.unwrap());
    let payloads = inbounds
        .iter()
        .flat_map(|inbound| inbound.events())
        .map(|event| event.payload.clone())
        .collect();
    let outcomes = inbounds
        .iter()
        .flat_map(|inbound| inbound.items.iter().map(|item| item.outcome.clone()))
        .collect();
    (payloads, outcomes)
}

/// One stranger identity, however many contexts it sends before Carol's, cannot use the room a
/// just-admitted member's first message needs (0142, 0146). Without the stranger the message is kept
/// too.
#[tokio::test]
async fn one_stranger_cannot_crowd_out_the_early_message_of_a_just_admitted_member() {
    for stranger_first in [false, true] {
        let mut a = carol_is_admitted_and_bob_is_not_told_yet().await;
        if stranger_first {
            let mut mallory = plain(a.directory, a.relay, "+mallory").await;
            let mallory_member = member_of(&mallory);
            for sequence in 0..4 {
                mallory
                    .send_as(
                        &a.bob_route,
                        &stranger_context(&mallory_member, &a.bob_member, sequence),
                        Kind::Group,
                    )
                    .await
                    .unwrap();
            }
            a.bob.receive(0).await.unwrap();
        }
        let (payloads, outcomes) = carol_writes_first(&mut a).await;
        assert!(
            payloads.iter().any(|payload| payload == b"carol says hi"),
            "stranger first {stranger_first}: Carol's message was lost: {outcomes:?}"
        );
        assert!(
            !payloads.iter().any(|payload| payload == b"stranger"),
            "a stranger's context is refused when the roster arrives"
        );
    }
}

/// The limit that remains, stated in 0142 and 0146: nothing before the roster arrives tells a
/// just-admitted member from a stranger, so two stranger identities take both slots that are open to
/// senders the roster does not list, and Carol's first message is refused and lost. This pins that
/// behaviour; it is not a guarantee.
#[tokio::test]
async fn two_stranger_identities_still_take_both_unlisted_slots_and_the_early_message_is_lost() {
    let mut a = carol_is_admitted_and_bob_is_not_told_yet().await;
    let mut first = plain(a.directory, a.relay, "+mallory").await;
    let mut second = plain(a.directory, a.relay, "+mallory2").await;
    for stranger in [&mut first, &mut second] {
        let member = member_of(stranger);
        stranger
            .send_as(
                &a.bob_route,
                &stranger_context(&member, &a.bob_member, 0),
                Kind::Group,
            )
            .await
            .unwrap();
    }
    let deferred = a.bob.receive(0).await.unwrap();
    assert!(
        deferred
            .items
            .iter()
            .all(|item| matches!(item.outcome, GroupOutcome::Deferred)),
        "{:?}",
        deferred.items
    );
    let (payloads, outcomes) = carol_writes_first(&mut a).await;
    assert!(
        outcomes.contains(&GroupOutcome::Rejected(
            tacenta_group::ReceiveRefusal::DeferredFull
        )),
        "{outcomes:?}"
    );
    assert!(
        !payloads.iter().any(|payload| payload == b"carol says hi"),
        "{payloads:?}"
    );
}
