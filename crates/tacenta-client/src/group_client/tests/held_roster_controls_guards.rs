//! Guards for the queue of held roster controls (decision 0142), the install order (decision 0141)
//! and the route check. They came from a mutation run of the second fix round, which found that no
//! test pinned them. Each test drives a real `GroupClient` against the in-process directory and
//! relay with the real provider.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc
//! comment is made.
//!
//! - The commit that drops the passed controls when a group is joined.
//! - A queue record that does not decode.
//! - A drain that cannot commit when a group is attached.
//! - A control a frozen drain left in the queue is applied by `recover` and by a restart.
//! - The IDs and the order of the events drained controls unlock.
//! - An expired invitee among the recipients of an install.
//! - A member removed two revisions ago is not told the next successor.
//! - A route to a device number below the member's.
//! - A coordinator with no view holds a control of a late revision.
//! - The entitlement of a recipient prepared on an installed roster honours the time it is given.
//! - A hold whose commit fails freezes the coordinator and does not consume the control.
//! - The queue record is replaced by an empty one when the queue empties.
//! - The events a drain unlocks at recovery are recorded, and offered by the next `receive`.
//! - A drain that cannot commit after an accepted roster freezes the batch.
//! - The commit that applies a held control drops the older held controls it passes.

use super::*;
use tacenta_core::crypto::groups::roster_commitment;

/// Successive rosters for a chain of `count` revisions after `genesis`, all with `members`.
pub(super) fn chain_after(genesis: &Roster, count: u64, members: &[Member]) -> Vec<Roster> {
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

pub(super) async fn send_control(sender: &mut DefaultClient, to: &DeviceAddr, roster: &Roster) {
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

/// A coordinator with no view that holds the controls for revisions 1 and 2.
async fn holding_one_and_two() -> (Setup, Vec<Roster>) {
    let mut s = setup(false).await;
    let chain = s.chain(3);
    s.send(&chain[0]).await;
    s.send(&chain[1]).await;
    s.carol.receive(0).await.unwrap();
    assert_eq!(s.carol.held_roster_controls(), [1, 2]);
    (s, chain)
}

/// In `commit_prune_deferred_rosters`, a commit that did not succeed is reported as `Policy`
/// instead of `Frozen`. Joining at revision 3 passes the controls held for 1 and 2 and the only
/// commit is the one that drops them; when it fails the caller must be told the coordinator is
/// frozen.
#[tokio::test]
async fn a_prune_commit_that_fails_when_the_group_is_joined_reports_frozen() {
    let (mut s, chain) = holding_one_and_two().await;
    s.carol_store.script([CommitOutcome::Failed], false);
    let failed = s
        .carol
        .join_group(chain[2].clone(), s.authority_member.clone());
    assert!(matches!(failed, Err(GroupError::Frozen)), "{failed:?}");
    assert!(s.carol.is_frozen());
}

/// In `commit_prune_deferred_rosters`, the coordinator's snapshot is not advanced after the
/// commit, so it reports the generation before the commit and builds its next commit on a snapshot
/// that still holds the passed controls.
#[tokio::test]
async fn the_coordinators_snapshot_follows_the_commit_that_drops_the_passed_controls() {
    let (mut s, chain) = holding_one_and_two().await;
    let before = s.carol.generation();
    s.carol
        .join_group(chain[2].clone(), s.authority_member.clone())
        .unwrap();
    assert_eq!(s.carol.roster().unwrap().revision, 3);
    assert!(s.carol.held_roster_controls().is_empty());
    let durable = s.carol_store.durable().unwrap();
    assert_eq!(durable.generation, before + 1);
    assert_eq!(s.carol.generation(), durable.generation);
}

/// In `recover_group_deferred_rosters`, a queue record that does not decode is read as an empty
/// queue, so a damaged record silently loses the held controls instead of failing the recovery.
#[tokio::test]
async fn a_queue_record_that_does_not_decode_fails_the_recovery() {
    let mut s = setup(true).await;
    let chain = s.chain(3);
    s.send(&chain[1]).await;
    s.carol.receive(0).await.unwrap();
    assert_eq!(s.carol.held_roster_controls(), [2]);
    let Setup {
        carol,
        carol_config,
        carol_store,
        genesis,
        authority_member,
        ..
    } = s;
    drop(carol);
    {
        let mut state = carol_store.0.lock().unwrap();
        let snapshot = state.snapshot.as_mut().unwrap();
        let record = snapshot
            .group_controls
            .iter_mut()
            .find(|record| record.starts_with(b"TCGQ"))
            .expect("the snapshot holds the queue record");
        record.pop();
    }
    let mut carol = restart(&carol_config, &carol_store).await;
    let failed = carol.join_group(genesis, authority_member);
    assert!(matches!(failed, Err(GroupError::Recovery)), "{failed:?}");
}

/// In `attach`, an error of the drain of held controls is ignored (`let _ =`), so a group is
/// reported joined although the control held for it could not be applied and the coordinator is
/// frozen.
#[tokio::test]
async fn a_drain_that_cannot_commit_when_the_group_is_joined_is_reported() {
    let mut s = setup(false).await;
    let chain = s.chain(1);
    s.send(&chain[0]).await;
    s.carol.receive(0).await.unwrap();
    assert_eq!(s.carol.held_roster_controls(), [1]);
    s.carol_store.script([CommitOutcome::Failed], false);
    let failed = s
        .carol
        .join_group(s.genesis.clone(), s.authority_member.clone());
    assert!(matches!(failed, Err(GroupError::Frozen)), "{failed:?}");
    assert!(s.carol.is_frozen());
}

/// A coordinator at revision 1 whose commit of the held revision 2 failed: revision 1 was accepted
/// (its commit landed) and the drain that would apply revision 2 froze the coordinator.
async fn frozen_between_revision_one_and_the_held_revision_two() -> Setup {
    let mut s = setup(true).await;
    let chain = s.chain(2);
    s.send(&chain[1]).await;
    s.carol.receive(0).await.unwrap();
    assert_eq!(s.carol.held_roster_controls(), [2]);
    s.carol_store
        .script([CommitOutcome::Committed, CommitOutcome::Failed], false);
    s.send(&chain[0]).await;
    let inbound = s.carol.receive(0).await.unwrap();
    assert!(inbound.frozen, "{inbound:?}");
    assert!(s.carol.is_frozen());
    let durable = s.carol_store.durable().unwrap();
    assert!(
        durable
            .group_controls
            .iter()
            .any(|record| record.starts_with(b"TCGV")),
        "the roster view of revision 1 is in the snapshot"
    );
    s
}

/// In `attach`, the held controls are applied only when the snapshot holds no roster view yet,
/// so `recover` (the view comes from the snapshot) leaves a control in the queue that a frozen drain
/// did not apply.
#[tokio::test]
async fn recover_applies_the_control_a_frozen_drain_left_in_the_queue() {
    let mut s = frozen_between_revision_one_and_the_held_revision_two().await;
    s.carol.recover().await.unwrap();
    assert!(!s.carol.is_frozen());
    assert_eq!(s.carol.roster().unwrap().revision, 2);
    assert!(s.carol.held_roster_controls().is_empty());
}

/// At a restart: the same, with the coordinator started again from its store.
#[tokio::test]
async fn a_restart_applies_the_control_a_frozen_drain_left_in_the_queue() {
    let s = frozen_between_revision_one_and_the_held_revision_two().await;
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
    assert_eq!(carol.roster().unwrap().revision, 2);
    assert!(carol.held_roster_controls().is_empty());
}

/// In `drain_deferred_rosters` the events a drained control unlocks are reported
/// with event ID 0 or newest first, and in `route` the events of the controls drained
/// behind an accepted roster are put before that roster's own. Bob is at revision 1 with
/// three messages waiting, one for revision 2 and two for revision 3; revision 3 arrives first and is
/// held, then revision 2 is accepted and revision 3 is drained behind it.
#[tokio::test]
async fn the_events_of_an_accepted_roster_and_of_the_control_drained_behind_it_keep_their_ids_and_order()
 {
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
    // Carol is told revisions 2 and 3 (Bob is not) and writes to Bob at each.
    let to_carol = [(carol_member.clone(), carol_route)];
    let r2 = alice.next_roster(members.clone()).unwrap();
    alice
        .install_roster(r2.clone(), &to_carol, None, 0)
        .await
        .unwrap();
    carol.receive(0).await.unwrap();
    let to_bob = [(bob_member.clone(), bob_route.clone())];
    carol
        .send_group(&to_bob, b"at revision two".to_vec())
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
        .send_group(&to_bob, b"three-a".to_vec())
        .await
        .unwrap();
    carol
        .send_group(&to_bob, b"three-b".to_vec())
        .await
        .unwrap();
    // Bob is at revision 1: all three messages are within two revisions and wait.
    let early = bob.receive(0).await.unwrap();
    assert!(
        matches!(
            outcomes(&early).as_slice(),
            [
                GroupOutcome::Deferred,
                GroupOutcome::Deferred,
                GroupOutcome::Deferred
            ]
        ),
        "{early:?}"
    );
    send_control(&mut alice.client, &bob_route, &r3).await;
    let held = bob.receive(0).await.unwrap();
    assert!(matches!(outcomes(&held).as_slice(), [held] if is_held(held)));
    send_control(&mut alice.client, &bob_route, &r2).await;
    let inbound = bob.receive(0).await.unwrap();
    assert_eq!(bob.roster().unwrap().revision, 3);
    let seen: Vec<(u64, Vec<u8>)> = inbound
        .events()
        .iter()
        .map(|event| (event.event_id, event.payload.clone()))
        .collect();
    assert_eq!(
        seen,
        [
            (0, b"at revision two".to_vec()),
            (1, b"three-a".to_vec()),
            (2, b"three-b".to_vec()),
        ],
        "{inbound:?}"
    );
}

/// In `install_roster`, the up-front check of the recipients is made at time 0, so an invitee
/// whose invitation has expired is still entitled to the successor there. The later per-recipient
/// check uses the real time and refuses it only after the first recipient has been prepared and the
/// successor installed, so the call is neither refused whole nor free of side effects.
#[tokio::test]
async fn an_expired_invitee_among_the_recipients_refuses_the_install_before_anything_changes() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, _bs) = joined(directory, relay, "+bob", &alice_member).await;
    let (bob_member, bob_route) = (bob.member().unwrap(), route(&bob));
    let dave = plain(directory, relay, "+dave").await;
    let (dave_member, dave_route) = (member_of(&dave), dave.address().clone());
    let r1 = alice
        .next_roster(vec![alice_member.clone(), bob_member.clone()])
        .unwrap();
    alice
        .install_roster(r1, &[(bob_member.clone(), bob_route.clone())], None, 0)
        .await
        .unwrap();
    bob.receive(0).await.unwrap();
    // Dave is invited at revision 1; the invitation expires at time 10. Revision 2 does not admit him.
    alice
        .invite(InvitationId::new([5; 16]), &dave_member, &dave_route, 10, 0)
        .await
        .unwrap();
    let r2 = alice
        .next_roster(vec![alice_member, bob_member.clone()])
        .unwrap();
    let both = [
        (bob_member.clone(), bob_route),
        (dave_member.clone(), dave_route),
    ];
    let before = alice.generation();
    let refused = alice.install_roster(r2.clone(), &both, None, 20).await;
    assert!(matches!(refused, Err(GroupError::Policy)), "{refused:?}");
    assert_eq!(alice.roster().unwrap().revision, 1);
    assert_eq!(alice.generation(), before, "nothing was committed");
    // Before it expires, the same call installs the successor and tells both.
    let install = alice.install_roster(r2, &both, None, 5).await.unwrap();
    assert_eq!(install.disposition, RosterDisposition::Accepted);
    assert_eq!(install.delivered.len(), 2, "{install:?}");
    assert!(install.pending.is_empty() && install.unprepared.is_empty());
}

/// In `roster_control_recipient_is_entitled`, the members of the roster the view replaced are
/// entitled even when the successor is not installed yet, so a member removed at revision 2 (a
/// member of revision 1) can be named as a recipient of revision 3. Only the successor being
/// installed admits the members of the roster it replaced (the member it removes).
#[tokio::test]
async fn a_member_removed_two_revisions_ago_is_not_told_the_next_successor() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let mut others = Vec::new();
    for index in 0..3 {
        let (client, _store) =
            joined(directory, relay, &format!("+member{index}"), &alice_member).await;
        let (member, member_route) = (client.member().unwrap(), route(&client));
        others.push((client, member, member_route));
    }
    let recipient = |index: usize| (others[index].1.clone(), others[index].2.clone());
    let everyone = vec![
        alice_member.clone(),
        others[0].1.clone(),
        others[1].1.clone(),
        others[2].1.clone(),
    ];
    let r1 = alice.next_roster(everyone).unwrap();
    let all = [recipient(0), recipient(1), recipient(2)];
    alice.install_roster(r1, &all, None, 0).await.unwrap();
    // Revision 2 removes member 1, and tells it so.
    let stays = vec![
        alice_member.clone(),
        others[0].1.clone(),
        others[2].1.clone(),
    ];
    let r2 = alice.next_roster(stays.clone()).unwrap();
    let install = alice.install_roster(r2, &all, None, 0).await.unwrap();
    assert_eq!(install.delivered.len(), 3, "{install:?}");
    // Revision 3 has the same members. Member 1 belongs to neither revision 2 nor revision 3, and
    // it is listed after a member that would be prepared first.
    let r3 = alice.next_roster(stays).unwrap();
    let before = alice.generation();
    let refused = alice
        .install_roster(r3, &[recipient(0), recipient(1)], None, 0)
        .await;
    assert!(matches!(refused, Err(GroupError::Policy)), "{refused:?}");
    assert_eq!(alice.roster().unwrap().revision, 2);
    assert_eq!(alice.generation(), before, "nothing was committed");
}

/// In `route_is_members_device`, `==` becomes `>=`, so a route to a device number below the
/// member's matches. The existing test uses a route to device 2 for a member on device 1 (which
/// `==` and `<=` refuse alike).
#[tokio::test]
async fn a_route_to_a_lower_device_number_than_the_members_is_refused() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    // Bob's only device is device 2.
    let mut bob = GroupClient::open(
        DefaultClient::connect(&config(directory, relay, "+bob", 2))
            .await
            .unwrap(),
        SharedStore::default(),
    )
    .await
    .unwrap();
    bob.join_group(genesis_of(&alice_member), alice_member.clone())
        .unwrap();
    let (bob_member, bob_route) = (bob.member().unwrap(), route(&bob));
    assert_eq!(bob_member.device(), &[2]);
    assert_eq!(bob_route.device, 2);
    let r1 = alice
        .next_roster(vec![alice_member, bob_member.clone()])
        .unwrap();
    alice
        .install_roster(r1, &[(bob_member.clone(), bob_route.clone())], None, 0)
        .await
        .unwrap();
    bob.receive(0).await.unwrap();
    let lower = DeviceAddr::new(bob_route.user.clone(), 1);
    let before = alice.generation();
    let refused = alice
        .send_group(&[(bob_member.clone(), lower)], b"for device two".to_vec())
        .await;
    assert!(matches!(refused, Err(GroupError::Policy)), "{refused:?}");
    assert_eq!(alice.generation(), before, "no intent was recorded");
    // The right route works.
    alice
        .send_group(&[(bob_member, bob_route)], b"for device two".to_vec())
        .await
        .unwrap();
    assert_eq!(bob.receive(0).await.unwrap().events().len(), 1);
}

/// In `commit_hold_roster_without_view`, a window is applied without a view (a revision above
/// 5 is refused). A coordinator that was invited at revision 6 has no roster to measure from, so it
/// must hold the revision-7 control that follows the source roster it will join from (0142).
#[tokio::test]
async fn a_coordinator_with_no_view_holds_a_control_of_a_late_revision() {
    let mut s = setup(false).await;
    let chain = s.chain(8);
    assert_eq!(chain[5].revision, 6);
    s.send(&chain[6]).await;
    let inbound = s.carol.receive(0).await.unwrap();
    assert!(
        matches!(outcomes(&inbound).as_slice(), [held] if is_held(held)),
        "{inbound:?}"
    );
    assert_eq!(s.carol.held_roster_controls(), [7]);
    s.carol
        .join_group(chain[5].clone(), s.authority_member.clone())
        .unwrap();
    assert_eq!(s.carol.roster().unwrap().revision, 7);
    assert!(s.carol.held_roster_controls().is_empty());
}

/// In `prepare_installed_roster_control`, the entitlement check is made at time 0, so an
/// invitee whose invitation has expired is still prepared a control on the installed roster. The
/// only caller, `install_roster`, checks every recipient first at the real time, so this is the
/// function's own guard (a second layer): it is pinned here by calling it directly.
#[tokio::test]
async fn an_expired_invitee_is_not_prepared_a_control_on_the_installed_roster() {
    let (directory, relay) = start_server().await;
    let mut alice = plain(directory, relay, "+alice").await;
    let bob = plain(directory, relay, "+bob").await;
    let (alice_member, bob_member) = (member_of(&alice), member_of(&bob));
    let bob_route = bob.address().clone();
    let genesis = genesis_of(&alice_member);
    let digest = roster_commitment(&genesis.encode().unwrap());
    let view = RosterView::accept_genesis(&alice_member, genesis, digest).unwrap();
    // Bob is invited at revision 0; the invitation expires at time 10. He is not in the roster.
    let mut book = InvitationBook::new(gid());
    let invitation = Invitation::new(
        InvitationId::new([3; 16]),
        gid(),
        bob_member.clone(),
        0,
        digest,
        POLICY_VERSION_V1,
        10,
    )
    .unwrap();
    book.create(
        &alice_member,
        &alice_member,
        std::slice::from_ref(&alice_member),
        invitation,
        0,
    )
    .unwrap();
    for (now, prepared) in [(9, true), (10, false)] {
        let mut store = SharedStore::default();
        let mut snapshot = OperationSnapshot::empty(0);
        let mut outbox = ControlOutbox::default();
        let result = prepare_installed_roster_control(
            &mut alice,
            &mut store,
            &mut snapshot,
            InstalledControlState {
                view: &view,
                outbox: &mut outbox,
                invitation_book: Some(&book),
                control_now: now,
            },
            &alice_member,
            (&bob_member, &bob_route),
        )
        .await;
        assert_eq!(result.is_ok(), prepared, "time {now}: {}", result.is_ok());
        if !prepared {
            assert!(matches!(result, Err(GroupLiveError::Policy)));
        }
    }
}

/// In `route`, a commit that fails while a control is held for want of a view is reported as a
/// refusal instead of an error, so the item is counted processed and acknowledged (the relay drops
/// it) although nothing was kept: the control is lost for good. It must freeze the coordinator and
/// leave the item at the relay, so that the control comes back after `recover`.
#[tokio::test]
async fn a_hold_whose_commit_fails_freezes_and_the_control_comes_back_after_recovery() {
    let mut s = setup(false).await;
    let chain = s.chain(1);
    s.send(&chain[0]).await;
    s.carol_store.script([CommitOutcome::Failed], false);
    let inbound = s.carol.receive(0).await.unwrap();
    assert!(inbound.frozen, "{inbound:?}");
    assert!(s.carol.is_frozen());
    assert!(s.carol.held_roster_controls().is_empty());
    s.carol.recover().await.unwrap();
    let inbound = s.carol.receive(0).await.unwrap();
    assert!(
        matches!(outcomes(&inbound).as_slice(), [held] if is_held(held)),
        "{inbound:?}"
    );
    assert_eq!(s.carol.held_roster_controls(), [1]);
}

/// The number of controls the queue record in the store's snapshot declares, once it has found
/// exactly one such record.
fn controls_in_the_queue_record(store: &SharedStore) -> u8 {
    let durable = store.durable().unwrap();
    let records: Vec<&Vec<u8>> = durable
        .group_controls
        .iter()
        .filter(|record| record.starts_with(b"TCGQ"))
        .collect();
    assert_eq!(records.len(), 1, "the checkpoint replaces its predecessor");
    records[0][4 + tacenta_group::GROUP_ID_LEN]
}

/// In `commit_roster_transition`, the queue record is not written when the queue becomes empty,
/// so the durable record keeps controls that were applied (here) or passed (below) until something
/// else changes the queue.
#[tokio::test]
async fn a_drain_that_empties_the_queue_replaces_its_record_with_an_empty_one() {
    let mut s = setup(true).await;
    let chain = s.chain(2);
    s.send(&chain[1]).await;
    s.carol.receive(0).await.unwrap();
    assert_eq!(s.carol.held_roster_controls(), [2]);
    assert_eq!(controls_in_the_queue_record(&s.carol_store), 1);
    s.send(&chain[0]).await;
    s.carol.receive(0).await.unwrap();
    assert_eq!(s.carol.roster().unwrap().revision, 2);
    assert!(s.carol.held_roster_controls().is_empty());
    assert_eq!(controls_in_the_queue_record(&s.carol_store), 0);
}

/// The other way to empty the queue: an accepted roster passes a held fork of its own revision.
#[tokio::test]
async fn an_accepted_roster_that_passes_the_held_control_replaces_its_record_with_an_empty_one() {
    let mut s = setup(true).await;
    let chain = s.chain(2);
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
    assert_eq!(s.carol.held_roster_controls(), [2]);
    assert_eq!(controls_in_the_queue_record(&s.carol_store), 1);
    s.send(&chain[1]).await;
    s.carol.receive(0).await.unwrap();
    assert_eq!(s.carol.roster().unwrap().revision, 2);
    assert!(s.carol.held_roster_controls().is_empty());
    assert_eq!(controls_in_the_queue_record(&s.carol_store), 0);
}

/// The events that the drain at `recover` unlocks are recorded with the transition and offered
/// by the next `receive`. Bob is at revision 1 with a message for revision 3 waiting; revision 3
/// reaches him first and is held; revision 2 is accepted and the commit that would apply revision 3
/// fails. `recover` applies revision 3, which accepts the waiting message.
#[tokio::test]
async fn the_events_a_drain_unlocks_at_recovery_are_offered_by_the_next_receive() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, bob_store) = joined(directory, relay, "+bob", &alice_member).await;
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
    let to_carol = [(carol_member, carol_route)];
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
            b"at revision three".to_vec(),
        )
        .await
        .unwrap();
    let early = bob.receive(0).await.unwrap();
    assert!(matches!(
        outcomes(&early).as_slice(),
        [GroupOutcome::Deferred]
    ));
    send_control(&mut alice.client, &bob_route, &r3).await;
    let held = bob.receive(0).await.unwrap();
    assert!(matches!(outcomes(&held).as_slice(), [held] if is_held(held)));
    // Revision 2 commits; the commit that applies the held revision 3 does not.
    bob_store.script([CommitOutcome::Committed, CommitOutcome::Failed], false);
    send_control(&mut alice.client, &bob_route, &r2).await;
    let frozen = bob.receive(0).await.unwrap();
    assert!(frozen.frozen, "{frozen:?}");
    assert!(frozen.events().is_empty());
    bob.recover().await.unwrap();
    assert_eq!(bob.roster().unwrap().revision, 3);
    let inbound = bob.receive(0).await.unwrap();
    assert_eq!(inbound.redelivered.len(), 1, "{inbound:?}");
    assert_eq!(inbound.redelivered[0].payload, b"at revision three");
    assert_eq!(inbound.redelivered[0].event_id, 0);
    assert_eq!(inbound.lost_events, 0);
}

/// In `route`, an error of the drain that follows an accepted roster is swallowed
/// (`unwrap_or_default`), so the item is reported and acknowledged as processed although the commit
/// that applies the next held control failed and the coordinator is frozen.
#[tokio::test]
async fn a_drain_that_cannot_commit_after_an_accepted_roster_freezes_the_batch() {
    let mut s = setup(true).await;
    let chain = s.chain(2);
    s.send(&chain[1]).await;
    s.carol.receive(0).await.unwrap();
    assert_eq!(s.carol.held_roster_controls(), [2]);
    s.carol_store
        .script([CommitOutcome::Committed, CommitOutcome::Failed], false);
    s.send(&chain[0]).await;
    let inbound = s.carol.receive(0).await.unwrap();
    assert!(inbound.frozen, "{inbound:?}");
    assert!(
        inbound.items.is_empty(),
        "the item whose drain failed is not reported as processed: {inbound:?}"
    );
    assert!(s.carol.is_frozen());
}

/// In `commit_roster_transition`, an accepted roster drops only the held control of its own
/// revision (`remove`) instead of every control it passes (`prune_through`). With no view, controls
/// for revisions 3 and 5 are held; joining from revision 4 applies revision 5, and the commit that
/// does so must also drop revision 3, which the source roster passed (0142, decision 3). Otherwise a
/// second commit is needed for the drop, and a crash between the two leaves a passed control in the
/// record.
#[tokio::test]
async fn the_commit_that_applies_a_held_control_drops_the_older_ones_it_passes() {
    let mut s = setup(false).await;
    let chain = s.chain(5);
    s.send(&chain[2]).await;
    s.send(&chain[4]).await;
    s.carol.receive(0).await.unwrap();
    assert_eq!(s.carol.held_roster_controls(), [3, 5]);
    let before = s.carol.generation();
    s.carol
        .join_group(chain[3].clone(), s.authority_member.clone())
        .unwrap();
    assert_eq!(s.carol.roster().unwrap().revision, 5);
    assert!(s.carol.held_roster_controls().is_empty());
    assert_eq!(
        s.carol.generation(),
        before + 1,
        "applying revision 5 and dropping revision 3 are one commit"
    );
    assert_eq!(controls_in_the_queue_record(&s.carol_store), 0);
}
