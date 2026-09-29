//! Roster controls that reach a coordinator ahead of their predecessor, or before it has a roster view
//! (decision 0142, `crates/tacenta-client/src/group_client.rs`, `group_operations.rs`): which are held,
//! what is written when one is held or dropped, and what a drained control unlocks.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made. They run the live coordinator against the in-process directory and relay; the authority
//! is a plain client that sends the controls by hand where a coordinator would send them in order.
//!
//! - R075: the events a drained control unlocks are not reported.
//! - R125, R127, R128: the hold window and the report of a control that is already held.
//! - R131, R146: a roster transition that does not change the queue writes no queue record, and a
//!   change replaces the previous queue record.
//! - R132: a control held next to a view survives a restart.
//! - R133, R134, R135, R136, R137, R138: what `commit_hold_roster_without_view` refuses, and what it
//!   commits with the control.
//! - R141, R143: joining at a revision drops the held controls the view has passed, in the record
//!   and in memory.
//!
//! The ids (`R###`) are those of the single-change mutation run against 341e2b0.

use super::*;
use tacenta_core::crypto::groups::roster_commitment;

/// Successive rosters for a chain of `count` revisions after `genesis`, all with `members`.
fn chain_after(genesis: &Roster, count: u64, members: &[Member]) -> Vec<Roster> {
    let mut rosters: Vec<Roster> = Vec::new();
    let mut predecessor = roster_commitment(&genesis.encode().unwrap());
    for offset in 1..=count {
        let next = Roster::new(
            genesis.group_id,
            genesis.revision + offset,
            predecessor,
            genesis.authority.clone(),
            POLICY_VERSION_V1,
            false,
            members.to_vec(),
        )
        .unwrap();
        predecessor = roster_commitment(&next.encode().unwrap());
        rosters.push(next);
    }
    rosters
}

async fn send_control(sender: &mut DefaultClient, to: &DeviceAddr, roster: &Roster) {
    sender
        .send_as(
            to,
            &GroupPayload::Roster(roster.clone()).encode().unwrap(),
            Kind::Group,
        )
        .await
        .unwrap();
}

fn outcomes(inbound: &Inbound) -> Vec<&GroupOutcome> {
    inbound.items.iter().map(|item| &item.outcome).collect()
}

fn is_held(outcome: &GroupOutcome) -> bool {
    matches!(outcome, GroupOutcome::RosterDeferred)
}

fn is_missing_predecessor(outcome: &GroupOutcome) -> bool {
    matches!(
        outcome,
        GroupOutcome::Roster {
            disposition: RosterDisposition::Rejected(RosterRefusal::MissingPredecessor),
            ..
        }
    )
}

/// A plain client as the authority, and a coordinator (Carol) in its group.
struct Setup {
    authority: DefaultClient,
    authority_member: Member,
    carol: GroupClient,
    carol_store: SharedStore,
    carol_config: Config,
    carol_route: DeviceAddr,
    genesis: Roster,
}

async fn setup(with_view: bool) -> Setup {
    let (directory, relay) = start_server().await;
    let authority = plain(directory, relay, "+authority").await;
    let authority_member = member_of(&authority);
    let carol_store = SharedStore::default();
    let mut carol = coordinator(directory, relay, "+carol", &carol_store).await;
    let genesis = genesis_of(&authority_member);
    if with_view {
        carol
            .join_group(genesis.clone(), authority_member.clone())
            .unwrap();
    } else {
        carol.await_group(gid(), authority_member.clone()).unwrap();
    }
    Setup {
        carol_route: route(&carol),
        carol_config: config(directory, relay, "+carol", 1),
        authority,
        authority_member,
        carol,
        carol_store,
        genesis,
    }
}

impl Setup {
    fn chain(&self, count: u64) -> Vec<Roster> {
        chain_after(
            &self.genesis,
            count,
            std::slice::from_ref(&self.authority_member),
        )
    }

    async fn send(&mut self, roster: &Roster) {
        send_control(&mut self.authority, &self.carol_route, roster).await;
    }
}

/// R124: in `commit_roster_transition`, an accepted roster prunes the queue only through the revision
/// the view had, so a held control for the revision now accepted (a fork of it, held earlier) stays in
/// the queue and is dropped by a second commit. The roster and the drop of what it passed are one
/// commit.
#[tokio::test]
async fn r124_an_accepted_roster_drops_the_held_fork_of_its_revision_in_the_same_commit() {
    let mut s = setup(true).await;
    let chain = s.chain(2);
    // A control for revision 2 that is not the successor of revision 1: it is held.
    let fork = Roster::new(
        gid(),
        2,
        [9; DIGEST_LEN],
        s.authority_member.clone(),
        POLICY_VERSION_V1,
        false,
        vec![s.authority_member.clone()],
    )
    .unwrap();
    s.send(&fork).await;
    s.send(&chain[0]).await;
    s.carol.receive(0).await.unwrap();
    assert_eq!(s.carol.roster().unwrap().revision, 1);
    assert_eq!(
        s.carol.held_roster_controls(),
        [2],
        "the fork is still held"
    );
    let before = s.carol.generation();
    s.send(&chain[1]).await;
    let inbound = s.carol.receive(0).await.unwrap();
    assert!(is_accepted(outcomes(&inbound)[0]), "{inbound:?}");
    assert_eq!(s.carol.roster().unwrap().revision, 2);
    assert!(s.carol.held_roster_controls().is_empty());
    assert_eq!(
        s.carol.generation(),
        before + 1,
        "the roster and the drop of the fork are one commit"
    );
}

/// R125: in `commit_roster_transition`, `candidate.revision > current_revision + 1` becomes `>=`, so
/// a control for the very next revision whose predecessor digest is not the view's (a fork of the
/// next revision, which no later control can repair) is held instead of refused.
#[tokio::test]
async fn r125_a_control_for_the_next_revision_with_another_predecessor_is_refused_not_held() {
    let mut s = setup(true).await;
    let fork = Roster::new(
        gid(),
        1,
        [1; DIGEST_LEN],
        s.authority_member.clone(),
        POLICY_VERSION_V1,
        false,
        vec![s.authority_member.clone()],
    )
    .unwrap();
    s.send(&fork).await;
    let inbound = s.carol.receive(0).await.unwrap();
    assert!(
        matches!(outcomes(&inbound).as_slice(), [refused] if is_missing_predecessor(refused)),
        "{inbound:?}"
    );
    assert!(s.carol.held_roster_controls().is_empty());
}

/// R127: in `commit_roster_transition`, the hold window `revision <= current + 1 + HOLD_AHEAD` is one
/// revision longer. With the queue empty, only the window refuses a control one past its end (the
/// earlier test filled the queue first, and a full queue refuses too).
#[tokio::test]
async fn r127_a_control_one_revision_past_the_hold_window_is_refused_when_the_queue_has_room() {
    let mut s = setup(true).await;
    let chain = s.chain(6);
    // The view is at revision 0: revision 5 is the last one held, revision 6 is not.
    s.send(&chain[5]).await;
    s.send(&chain[4]).await;
    let inbound = s.carol.receive(0).await.unwrap();
    assert!(
        matches!(
            outcomes(&inbound).as_slice(),
            [refused, held] if is_missing_predecessor(refused) && is_held(held)
        ),
        "{inbound:?}"
    );
    assert_eq!(s.carol.held_roster_controls(), [5]);
}

/// R128: in `commit_roster_transition`, `Hold::Duplicate` no longer counts as held, so a control that
/// arrives twice is held the first time and reported refused the second.
#[tokio::test]
async fn r128_a_held_control_that_arrives_again_is_still_reported_held() {
    let mut s = setup(true).await;
    let chain = s.chain(3);
    s.send(&chain[1]).await;
    s.send(&chain[1]).await;
    let inbound = s.carol.receive(0).await.unwrap();
    assert!(
        matches!(outcomes(&inbound).as_slice(), [first, again] if is_held(first) && is_held(again)),
        "{inbound:?}"
    );
    assert_eq!(s.carol.held_roster_controls(), [2]);
}

fn queue_records(client: &GroupClient) -> usize {
    client
        .snapshot
        .group_controls
        .iter()
        .filter(|record| record.starts_with(b"TCGQ"))
        .count()
}

/// R131: in `commit_roster_transition`, the queue record is written whether or not the queue
/// changed, so every roster a coordinator accepts adds a record to the bounded control records.
#[tokio::test]
async fn r131_a_roster_that_leaves_the_queue_unchanged_writes_no_queue_record() {
    let mut s = setup(true).await;
    let chain = s.chain(1);
    s.send(&chain[0]).await;
    let inbound = s.carol.receive(0).await.unwrap();
    assert!(is_accepted(outcomes(&inbound)[0]));
    assert_eq!(s.carol.roster().unwrap().revision, 1);
    assert_eq!(queue_records(&s.carol), 0);
}

fn is_accepted(outcome: &GroupOutcome) -> bool {
    matches!(
        outcome,
        GroupOutcome::Roster {
            disposition: RosterDisposition::Accepted,
            ..
        }
    )
}

/// R146: `CHECKPOINT_TAGS` no longer lists `TCGQ`, so each change to the queue adds a record beside
/// the previous one.
#[tokio::test]
async fn r146_each_change_of_the_queue_replaces_its_record() {
    let mut s = setup(true).await;
    let chain = s.chain(4);
    s.send(&chain[1]).await;
    s.carol.receive(0).await.unwrap();
    assert_eq!(s.carol.held_roster_controls(), [2]);
    s.send(&chain[2]).await;
    s.carol.receive(0).await.unwrap();
    assert_eq!(s.carol.held_roster_controls(), [2, 3]);
    assert_eq!(queue_records(&s.carol), 1);
}

/// R132: in `commit_roster_transition`, a change of the queue is never written, so the controls a
/// coordinator with a view holds are lost when it restarts.
#[tokio::test]
async fn r132_controls_held_next_to_a_view_survive_a_restart() {
    let mut s = setup(true).await;
    let chain = s.chain(3);
    s.send(&chain[1]).await;
    s.send(&chain[2]).await;
    s.carol.receive(0).await.unwrap();
    assert_eq!(s.carol.held_roster_controls(), [2, 3]);
    let Setup {
        carol,
        carol_config,
        carol_store,
        genesis,
        authority_member,
        ..
    } = s;
    drop(carol);
    let mut carol = restart(&carol_config, &carol_store).await;
    carol.join_group(genesis, authority_member).unwrap();
    assert_eq!(carol.held_roster_controls(), [2, 3]);
}

/// R075: in `route`, `events.extend(drain_deferred_rosters(..)?)` becomes a call that drops the
/// events, so the application messages that a drained control accepts are committed (their event IDs
/// consumed) and never reported.
#[tokio::test]
async fn r075_the_events_a_drained_control_unlocks_are_reported() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, _bs) = joined(directory, relay, "+bob", &alice_member).await;
    let (mut carol, _cs) = joined(directory, relay, "+carol", &alice_member).await;
    let (bob_member, bob_route) = (bob.member().unwrap(), route(&bob));
    let (carol_member, carol_route) = (carol.member().unwrap(), route(&carol));
    let members = vec![alice_member, bob_member.clone(), carol_member.clone()];
    let told_both = [
        (bob_member.clone(), bob_route.clone()),
        (carol_member.clone(), carol_route.clone()),
    ];
    let r1 = alice.next_roster(members.clone()).unwrap();
    alice.install_roster(r1, &told_both, None, 0).await.unwrap();
    bob.receive(0).await.unwrap();
    carol.receive(0).await.unwrap();
    // Revisions 2 and 3 are told to Carol only.
    let to_carol = [(carol_member.clone(), carol_route)];
    let r2 = alice.next_roster(members.clone()).unwrap();
    alice
        .install_roster(r2.clone(), &to_carol, None, 0)
        .await
        .unwrap();
    let r3 = alice.next_roster(members).unwrap();
    alice
        .install_roster(r3.clone(), &to_carol, None, 0)
        .await
        .unwrap();
    carol.receive(0).await.unwrap();
    assert_eq!(carol.roster().unwrap().revision, 3);
    carol
        .send_group(
            &[(bob_member, bob_route.clone())],
            b"carol at revision three".to_vec(),
        )
        .await
        .unwrap();
    // Bob is at revision 1: the message is two revisions ahead and waits.
    let early = bob.receive(0).await.unwrap();
    assert!(matches!(
        outcomes(&early).as_slice(),
        [GroupOutcome::Deferred]
    ));
    // Revision 3 reaches him before revision 2 and is held.
    send_control(&mut alice.client, &bob_route, &r3).await;
    let held = bob.receive(0).await.unwrap();
    assert!(matches!(outcomes(&held).as_slice(), [held] if is_held(held)));
    assert_eq!(bob.held_roster_controls(), [3]);
    // Revision 2 applies, revision 3 is drained behind it, and the message it unlocks is reported.
    send_control(&mut alice.client, &bob_route, &r2).await;
    let inbound = bob.receive(0).await.unwrap();
    assert_eq!(bob.roster().unwrap().revision, 3);
    assert!(bob.held_roster_controls().is_empty());
    let events = inbound.events();
    assert_eq!(events.len(), 1, "{inbound:?}");
    assert_eq!(events[0].payload, b"carol at revision three");
    assert_eq!(events[0].sender, carol_member);
}

/// R133: in `commit_hold_roster_without_view`, the check that the control is for the group being
/// awaited is removed, so a control of another group from the authority is held.
#[tokio::test]
async fn r133_a_control_of_another_group_is_not_held_without_a_view() {
    let mut s = setup(false).await;
    let foreign = Roster::new(
        GroupId::new(*b"another-group-id"),
        1,
        [1; DIGEST_LEN],
        s.authority_member.clone(),
        POLICY_VERSION_V1,
        false,
        vec![s.authority_member.clone()],
    )
    .unwrap();
    s.send(&foreign).await;
    let inbound = s.carol.receive(0).await.unwrap();
    assert!(
        matches!(outcomes(&inbound).as_slice(), [GroupOutcome::Refused]),
        "{inbound:?}"
    );
    assert!(s.carol.held_roster_controls().is_empty());
}

/// R134: in `commit_hold_roster_without_view`, the check that the control names the pinned authority
/// is removed, so a control that names another member as authority, sent by the authority, is held.
#[tokio::test]
async fn r134_a_control_that_names_another_authority_is_not_held_without_a_view() {
    let mut s = setup(false).await;
    let usurper = Member::new(b"someone else".to_vec(), vec![1]);
    let control = Roster::new(
        gid(),
        1,
        [1; DIGEST_LEN],
        usurper.clone(),
        POLICY_VERSION_V1,
        false,
        vec![usurper],
    )
    .unwrap();
    s.send(&control).await;
    let inbound = s.carol.receive(0).await.unwrap();
    assert!(
        matches!(outcomes(&inbound).as_slice(), [GroupOutcome::Refused]),
        "{inbound:?}"
    );
    assert!(s.carol.held_roster_controls().is_empty());
}

/// R135: in `commit_hold_roster_without_view`, the refusal of a revision-zero control is removed, so
/// a genesis-shaped control is held although no view can follow it.
#[tokio::test]
async fn r135_a_revision_zero_control_is_not_held_without_a_view() {
    let mut s = setup(false).await;
    let genesis = s.genesis.clone();
    s.send(&genesis).await;
    let inbound = s.carol.receive(0).await.unwrap();
    assert!(
        matches!(outcomes(&inbound).as_slice(), [GroupOutcome::Refused]),
        "{inbound:?}"
    );
    assert!(s.carol.held_roster_controls().is_empty());
}

/// R136: in `commit_hold_roster_without_view`, `Hold::Duplicate` is no longer accepted, so a control
/// that arrives twice is held the first time and refused the second.
#[tokio::test]
async fn r136_a_control_held_without_a_view_that_arrives_again_is_still_held() {
    let mut s = setup(false).await;
    let chain = s.chain(2);
    s.send(&chain[0]).await;
    s.send(&chain[0]).await;
    let inbound = s.carol.receive(0).await.unwrap();
    assert!(
        matches!(outcomes(&inbound).as_slice(), [first, again] if is_held(first) && is_held(again)),
        "{inbound:?}"
    );
    assert_eq!(s.carol.held_roster_controls(), [1]);
}

/// R137: in `commit_hold_roster_without_view`, the provider state that consumed the control's
/// ciphertext is not committed with the queue, so a restart would decrypt from a position the
/// control already used.
#[tokio::test]
async fn r137_a_hold_commits_the_provider_state_that_consumed_the_control() {
    let mut s = setup(false).await;
    let chain = s.chain(1);
    s.send(&chain[0]).await;
    s.carol.receive(0).await.unwrap();
    assert_eq!(s.carol.held_roster_controls(), [1]);
    let durable = s.carol_store.durable().unwrap();
    assert_eq!(
        durable.provider_state,
        s.carol.client.export_state().await.unwrap()
    );
}

/// R138: in `commit_hold_roster_without_view`, the record of the crypto-state effect is not written
/// beside the queue record.
#[tokio::test]
async fn r138_a_hold_commits_the_effect_record_next_to_the_queue_record() {
    let mut s = setup(false).await;
    let chain = s.chain(1);
    s.send(&chain[0]).await;
    s.carol.receive(0).await.unwrap();
    let controls = s.carol_store.durable().unwrap().group_controls;
    let queue = controls
        .iter()
        .position(|record| record.starts_with(b"TCGQ"))
        .expect("the queue is recorded");
    assert!(
        queue > 0 && controls[queue - 1].starts_with(b"TCGE"),
        "{controls:?}"
    );
}

/// A coordinator without a view that holds the controls for revisions 1 and 2, then joins from a
/// source roster at revision 2: the view has passed both.
async fn joined_from_revision_two() -> (Setup, Vec<Roster>) {
    let mut s = setup(false).await;
    let chain = s.chain(2);
    s.send(&chain[0]).await;
    s.send(&chain[1]).await;
    s.carol.receive(0).await.unwrap();
    assert_eq!(s.carol.held_roster_controls(), [1, 2]);
    s.carol
        .join_group(chain[1].clone(), s.authority_member.clone())
        .unwrap();
    assert_eq!(s.carol.roster().unwrap().revision, 2);
    (s, chain)
}

/// R141: in `commit_prune_deferred_rosters`, the queue is pruned only through the revision below the
/// view's, so the control for the view's own revision stays in the record and comes back after a
/// restart.
#[tokio::test]
async fn r141_joining_at_a_revision_drops_the_held_control_for_that_revision_from_the_record() {
    let (s, chain) = joined_from_revision_two().await;
    assert!(s.carol.held_roster_controls().is_empty());
    let Setup {
        carol,
        carol_config,
        carol_store,
        authority_member,
        ..
    } = s;
    drop(carol);
    let mut carol = restart(&carol_config, &carol_store).await;
    carol
        .join_group(chain[1].clone(), authority_member)
        .unwrap();
    assert!(carol.held_roster_controls().is_empty());
}

/// R143: in `commit_prune_deferred_rosters`, the queue in memory is not replaced after the record is
/// committed, so a coordinator still reports the controls the view has passed as held.
#[tokio::test]
async fn r143_joining_at_a_revision_drops_the_passed_controls_from_memory() {
    let (s, _chain) = joined_from_revision_two().await;
    assert!(s.carol.held_roster_controls().is_empty());
}
