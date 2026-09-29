//! Dispatching group sends and roster controls through `GroupClient`
//! (`crates/tacenta-client/src/group_client.rs`, `group_operations.rs`, `group_control_outbox.rs`):
//! a refused recipient does not stop the batch, and a send or control whose relay acceptance was
//! lost (`HandedOff`) is retried as it is.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made. They run the live coordinator against the in-process directory and relay.
//!
//! - M026 (`group_client.rs:1307`): `drive_send` returns on the first refused recipient.
//! - M075 (`group_operations.rs:537`): `prepare_control_handoff` does not return a handed-off
//!   control as it is.
//! - M076 (`group_operations.rs:1270`): `prepare_outbox_group_recipient` refuses a handed-off
//!   recipient.
//! - M108 (`group_control_outbox.rs:40`): `Disposition::is_terminal` counts `HandedOff` as
//!   terminal.
//!
//! The ids (`M###`, `D##`) are those of the single-change mutation run against 97689a0; the
//! `file:line` in each test's doc comment is the change site at that commit.

use super::*;

/// M026 (`group_client.rs:1307`): in `drive_send`, `Err(_) => continue,` after
/// `prepare_outbox_group_recipient` becomes `Err(_) => return Ok(()),`, so a recipient that is
/// refused (here: already relay-accepted, hence terminal) stops the batch and the recipients after
/// it are never driven.
#[tokio::test]
async fn m026_a_finished_recipient_does_not_stop_the_batch_for_the_next_one() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, _) = joined(directory, relay, "+bob", &alice_member).await;
    let (mut carol, _) = joined(directory, relay, "+carol", &alice_member).await;
    let (bob_member, carol_member) = (bob.member().unwrap(), carol.member().unwrap());
    let routes = vec![
        (bob_member.clone(), route(&bob)),
        (carol_member.clone(), route(&carol)),
    ];
    let r1 = alice
        .next_roster(vec![
            alice_member.clone(),
            bob_member.clone(),
            carol_member.clone(),
        ])
        .unwrap();
    let installed = alice.install_roster(r1, &routes, None, 0).await.unwrap();
    assert_eq!(installed.delivered.len(), 2);
    for receiver in [&mut bob, &mut carol] {
        assert_eq!(
            sole_roster_disposition(&receiver.receive(0).await.unwrap()),
            RosterDisposition::Accepted
        );
    }

    // Recipients are driven in canonical order. Let the first finish and the
    // second's preparation be in doubt.
    let bob_first = bob_member.canonical_cmp(&carol_member) == std::cmp::Ordering::Less;
    alice_store.script(
        [
            CommitOutcome::Committed, // the intent
            CommitOutcome::Committed, // first recipient prepared
            CommitOutcome::Committed, // first recipient reserved
            CommitOutcome::Committed, // first recipient relay-accepted
            CommitOutcome::Unknown,   // second recipient prepared: in doubt, lost
        ],
        false,
    );
    assert!(matches!(
        alice.send_group(&routes, b"both".to_vec()).await,
        Err(GroupError::Frozen)
    ));
    alice.recover().await.unwrap();

    // The first recipient is terminal; the second must still be driven.
    assert_eq!(
        alice.dispatch_pending_group_sends(&routes).await.unwrap(),
        1
    );
    let (first, second) = if bob_first {
        (&mut bob, &mut carol)
    } else {
        (&mut carol, &mut bob)
    };
    assert_eq!(first.receive(0).await.unwrap().events()[0].payload, b"both");
    assert_eq!(
        second.receive(0).await.unwrap().events()[0].payload,
        b"both"
    );
}

/// M075 (`group_operations.rs:537`): in `prepare_control_handoff`, the match on
/// `ControlDisposition::Prepared | ControlDisposition::HandedOff` loses `HandedOff`, so an exact
/// control that is already handed off is not returned as it is; it goes to the dry-run commit,
/// which conflicts with the stored ciphertext, and installing again fails with `Policy`.
#[tokio::test]
async fn m075_a_control_whose_acceptance_was_lost_is_retried_by_installing_again() {
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

    // Installation+prepared, reservation (hand-off) commit; the acceptance is lost.
    alice_store.script(
        [
            CommitOutcome::Committed,
            CommitOutcome::Committed,
            CommitOutcome::Unknown,
        ],
        false,
    );
    assert!(matches!(
        alice.install_roster(r1.clone(), &routes, None, 0).await,
        Err(GroupError::Frozen)
    ));
    alice.recover().await.unwrap();
    assert_eq!(alice.roster().unwrap().revision, 1);

    // The control is `handed_off` after recovery; installing again retries it.
    let again = alice.install_roster(r1, &routes, None, 0).await.unwrap();
    assert_eq!(again.delivered, vec![bob_member], "{again:?}");
    assert!(again.pending.is_empty());
    assert!(!bob.receive(0).await.unwrap().items.is_empty());
}

/// M076 (`group_operations.rs:1270`): in `prepare_outbox_group_recipient`,
/// `RecipientDisposition::Prepared | RecipientDisposition::HandedOff => return
/// Ok(progress.clone())` no longer includes `HandedOff`, which falls into the `Err(Policy)` arm, so
/// a recipient whose acceptance was lost is never retried.
#[tokio::test]
async fn m076_a_group_send_whose_acceptance_was_lost_is_retried() {
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

    // Intent, prepared ciphertext and reservation commit; the relay accepts the
    // send but the acceptance commit is lost.
    alice_store.script(
        [
            CommitOutcome::Committed,
            CommitOutcome::Committed,
            CommitOutcome::Committed,
            CommitOutcome::Unknown,
        ],
        false,
    );
    assert!(matches!(
        alice.send_group(&routes, b"resent".to_vec()).await,
        Err(GroupError::Frozen)
    ));
    alice.recover().await.unwrap();
    let id = alice.group.as_ref().unwrap().outbox.sends()[0].id.clone();
    assert_eq!(
        alice.group.as_ref().unwrap().outbox.sends()[0].recipients()[0].disposition,
        RecipientDisposition::HandedOff
    );

    assert_eq!(
        alice.dispatch_pending_group_sends(&routes).await.unwrap(),
        1
    );
    let group = alice.group.as_ref().unwrap();
    assert_eq!(
        group.outbox.send(&id).unwrap().recipients()[0].disposition,
        RecipientDisposition::RelayAccepted
    );
    assert_eq!(
        group.outbox.send(&id).unwrap().recipients()[0].attempts_reserved,
        2
    );
    assert!(!bob.receive(0).await.unwrap().events().is_empty());
}

/// M108 (`group_control_outbox.rs:40`): `Disposition::is_terminal` becomes `!matches!(self,
/// Disposition::Prepared)`, so a handed-off control counts as terminal: `pending()` no longer lists
/// it and `dispatch_pending_controls` never retries a control whose acceptance was lost (the count
/// is 0, not 1).
#[tokio::test]
async fn m108_dispatch_pending_controls_retries_a_handed_off_control() {
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
    alice_store.script(
        [
            CommitOutcome::Committed,
            CommitOutcome::Committed,
            CommitOutcome::Unknown,
        ],
        false,
    );
    assert!(matches!(
        alice.install_roster(r1, &routes, None, 0).await,
        Err(GroupError::Frozen)
    ));
    alice.recover().await.unwrap();
    assert_eq!(alice.dispatch_pending_controls(&routes).await.unwrap(), 1);
    assert!(!bob.receive(0).await.unwrap().items.is_empty());
    assert_eq!(alice.dispatch_pending_controls(&routes).await.unwrap(), 0);
}
