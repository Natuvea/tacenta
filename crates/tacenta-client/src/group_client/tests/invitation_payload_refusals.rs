//! Invitation payloads that the receive path of `GroupClient` must refuse without poisoning the
//! coordinator (`crates/tacenta-client/src/group_client.rs`, `route`), and two payloads that the
//! commit functions of `group_operations.rs` must refuse.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made. They run the live coordinator against the in-process directory and relay.
//!
//! - M030 (`group_client.rs:767`), M031 (`group_client.rs:781`), M032 (`group_client.rs:796`): the
//!   bootstrap, acceptance or revocation arm of `route` turns a policy refusal into a hard error,
//!   which poisons the coordinator, stops the batch and makes `receive` return `Err`.
//! - M101 (`group_operations.rs:960`): a bootstrap whose source roster is closed is recorded.
//! - M102 (`group_operations.rs:1028`): an acceptance naming another group is applied.
//!
//! The ids (`M###`, `D##`) are those of the single-change mutation run against 97689a0; the
//! `file:line` in each test's doc comment is the change site at that commit.

use super::*;
use tacenta_group::InvitationRevocation;

/// Asserts the one item `receiver` was sent is a `Refused` and that the
/// coordinator is still running.
async fn assert_refused_and_running(receiver: &mut GroupClient) {
    let inbound = receiver
        .receive(1)
        .await
        .expect("a refusal is not an error");
    assert!(
        matches!(
            inbound.items.as_slice(),
            [GroupReceipt {
                outcome: GroupOutcome::Refused,
                ..
            }]
        ),
        "{inbound:?}"
    );
    assert!(!inbound.frozen);
    assert!(!receiver.is_frozen(), "a refused payload must not poison");
}

/// M030 (`group_client.rs:767`): in `route`, the `InvitationBootstrap` arm's
/// `Err(GroupOperationError::Policy) => Ok(GroupOutcome::Refused)` becomes `=>
/// Err(GroupOperationError::Policy)`, so an authenticated bootstrap that the policy refuses is a
/// hard error: `stage` poisons the coordinator, the batch stops and `receive` returns `Err`.
#[tokio::test]
async fn m030_a_bootstrap_addressed_to_someone_else_is_refused_and_does_not_poison() {
    let (directory, relay) = start_server().await;
    let mut alice = plain(directory, relay, "+alice").await;
    let carol = plain(directory, relay, "+carol").await;
    let store = SharedStore::default();
    let mut bob = coordinator(directory, relay, "+bob", &store).await;
    let alice_member = member_of(&alice);
    bob.await_group(gid(), alice_member.clone()).unwrap();

    // Authentic (from the pinned authority) but for Carol, not for Bob.
    let genesis = genesis_of(&alice_member);
    let digest = roster_commitment(&genesis.encode().unwrap());
    let invitation = Invitation::new(
        InvitationId::new([9; 16]),
        gid(),
        member_of(&carol),
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
    alice
        .send_as(bob.address(), &bootstrap, Kind::Group)
        .await
        .unwrap();
    assert_refused_and_running(&mut bob).await;
    assert!(bob.invitations().is_empty());
}

/// M031 (`group_client.rs:781`): the same change in the `InvitationAcceptance` arm of `route`.
#[tokio::test]
async fn m031_an_acceptance_for_an_unknown_invitation_is_refused_and_does_not_poison() {
    let (directory, relay) = start_server().await;
    let store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &store).await;
    alice.create_group(gid()).unwrap();
    let mut mallory = plain(directory, relay, "+mallory").await;

    let acceptance = GroupPayload::InvitationAcceptance(
        InvitationAcceptance::new(gid(), InvitationId::new([9; 16]), 0, [0; DIGEST_LEN]).unwrap(),
    )
    .encode()
    .unwrap();
    mallory
        .send_as(alice.address(), &acceptance, Kind::Group)
        .await
        .unwrap();
    assert_refused_and_running(&mut alice).await;
}

/// M032 (`group_client.rs:796`): the same change in the `InvitationRevocation` arm of `route`.
#[tokio::test]
async fn m032_a_revocation_for_an_unknown_invitation_is_refused_and_does_not_poison() {
    let (directory, relay) = start_server().await;
    let mut alice = plain(directory, relay, "+alice").await;
    let store = SharedStore::default();
    let mut bob = coordinator(directory, relay, "+bob", &store).await;
    bob.await_group(gid(), member_of(&alice)).unwrap();

    let revocation = GroupPayload::InvitationRevocation(
        InvitationRevocation::new(gid(), InvitationId::new([9; 16]), 0, [0; DIGEST_LEN]).unwrap(),
    )
    .encode()
    .unwrap();
    alice
        .send_as(bob.address(), &revocation, Kind::Group)
        .await
        .unwrap();
    assert_refused_and_running(&mut bob).await;
}

/// M101 (`group_operations.rs:960`): in `commit_group_invitation_bootstrap`, `||
/// bootstrap.source_roster.closed` is removed from the refusal condition, so a bootstrap whose
/// source roster is closed (which `join_group` would later refuse with `InvalidSource`) is recorded
/// as a pending invitation.
#[tokio::test]
async fn m101_a_bootstrap_whose_source_roster_is_closed_is_refused() {
    let (directory, relay) = start_server().await;
    let mut alice = plain(directory, relay, "+alice").await;
    let store = SharedStore::default();
    let mut bob = coordinator(directory, relay, "+bob", &store).await;
    let alice_member = member_of(&alice);
    bob.await_group(gid(), alice_member.clone()).unwrap();

    let closed = Roster::new(
        gid(),
        1,
        [0; DIGEST_LEN],
        alice_member.clone(),
        POLICY_VERSION_V1,
        true,
        vec![alice_member.clone()],
    )
    .unwrap();
    let digest = roster_commitment(&closed.encode().unwrap());
    let invitation = Invitation::new(
        InvitationId::new([9; 16]),
        gid(),
        bob.member().unwrap(),
        1,
        digest,
        POLICY_VERSION_V1,
        100,
    )
    .unwrap();
    let bootstrap =
        GroupPayload::InvitationBootstrap(InvitationBootstrap::new(invitation, closed).unwrap())
            .encode()
            .unwrap();
    alice
        .send_as(bob.address(), &bootstrap, Kind::Group)
        .await
        .unwrap();
    let inbound = bob.receive(1).await.unwrap();
    assert!(
        matches!(
            inbound.items.as_slice(),
            [GroupReceipt {
                outcome: GroupOutcome::Refused,
                ..
            }]
        ),
        "{inbound:?}"
    );
    assert!(bob.invitations().is_empty());
}

/// M102 (`group_operations.rs:1028`): in `commit_group_invitation_acceptance`, the block that
/// refuses an acceptance whose `group_id` differs from the book's is removed, so an acceptance
/// naming another group is applied to the invitation it names.
#[tokio::test]
async fn m102_an_acceptance_naming_another_group_is_refused() {
    let (directory, relay) = start_server().await;
    let store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &store).await;
    alice.create_group(gid()).unwrap();
    let mut bob = plain(directory, relay, "+bob").await;
    let bob_member = member_of(&bob);
    let bootstrap = alice
        .invite(
            InvitationId::new([9; 16]),
            &bob_member,
            bob.address(),
            100,
            0,
        )
        .await
        .unwrap();

    let acceptance = GroupPayload::InvitationAcceptance(
        InvitationAcceptance::new(
            GroupId::new(*b"another-group-id"),
            InvitationId::new([9; 16]),
            bootstrap.invitation.source_revision,
            bootstrap.invitation.source_roster_digest,
        )
        .unwrap(),
    )
    .encode()
    .unwrap();
    bob.send_as(alice.address(), &acceptance, Kind::Group)
        .await
        .unwrap();
    let inbound = alice.receive(1).await.unwrap();
    assert!(
        matches!(
            inbound.items.as_slice(),
            [GroupReceipt {
                outcome: GroupOutcome::Refused,
                ..
            }]
        ),
        "{inbound:?}"
    );
    assert_eq!(alice.invitations()[0].status, InvitationStatus::Pending);
}
