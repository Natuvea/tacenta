//! The route checks of decision 0141 on the invitation calls and on `dispatch_pending_group_sends`,
//! and the authority check of `install_roster` (`crates/tacenta-client/src/group_client.rs`).
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made. They run the live coordinator against the in-process directory and relay.
//!
//! - R076: `route_is_members_device` matches a member with several device bytes on its first.
//! - R082, R084, R085: `invite`, `accept_invitation` or `revoke_invitation` does not check that the
//!   route is the device of the member it names.
//! - R096: `install_roster` does not refuse a coordinator that is not the authority.
//!
//! The ids (`R###`) are those of the single-change mutation run against 341e2b0.

use super::*;

/// A second device of the same user and identity: a route that is not the member's device.
async fn second_device(
    directory: SocketAddr,
    relay: SocketAddr,
    user: &str,
    identity: &[u8],
) -> DefaultClient {
    DefaultClient::connect_with_identity(&config(directory, relay, user, 2), identity)
        .await
        .unwrap()
}

/// R076: in `route_is_members_device`, the pattern `[device]` becomes `[device, ..]`, so a member
/// that carries several device bytes is matched by the first of them.
#[tokio::test]
async fn r076_a_member_with_several_device_bytes_is_not_matched_by_its_first_route() {
    let (directory, relay) = start_server().await;
    let store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &store).await;
    alice.create_group(gid()).unwrap();
    let odd = Member::new(b"someone".to_vec(), vec![1, 2]);
    let refused = alice
        .dispatch_pending_group_sends(&[(odd, DeviceAddr::new("+bob", 1))])
        .await;
    assert!(matches!(refused, Err(GroupError::Policy)), "{refused:?}");
}

/// R082: in `invite`, `|| !route_is_members_device(target, route)` is removed from the refusal
/// condition, so an invitation is recorded and its bootstrap sent to a route that is not the
/// target's device.
#[tokio::test]
async fn r082_an_invitation_to_a_route_that_is_not_the_targets_device_is_refused() {
    let (directory, relay) = start_server().await;
    let store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &store).await;
    alice.create_group(gid()).unwrap();
    let dave = plain(directory, relay, "+dave").await;
    let dave_member = member_of(&dave);
    let mut dave_two = second_device(directory, relay, "+dave", &dave.export_identity()).await;
    let before = alice.generation();
    let refused = alice
        .invite(
            InvitationId::new([9; 16]),
            &dave_member,
            dave_two.address(),
            100,
            0,
        )
        .await;
    assert!(matches!(refused, Err(GroupError::Policy)), "{refused:?}");
    assert!(alice.invitations().is_empty());
    assert_eq!(alice.generation(), before, "nothing was committed");
    assert_eq!(dave_two.drain().await.unwrap().len(), 0, "nothing was sent");
}

/// R084: in `accept_invitation`, the check that the authority's route is the authority's device is
/// replaced by `false`, so the acceptance is recorded before its control fails to reach anyone.
#[tokio::test]
async fn r084_an_acceptance_to_a_route_that_is_not_the_authoritys_device_is_refused() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let bob_store = SharedStore::default();
    let mut bob = coordinator(directory, relay, "+bob", &bob_store).await;
    bob.await_group(gid(), alice_member).unwrap();
    let bob_member = bob.member().unwrap();
    alice
        .invite(
            InvitationId::new([9; 16]),
            &bob_member,
            &route(&bob),
            100,
            0,
        )
        .await
        .unwrap();
    bob.receive(1).await.unwrap();
    assert_eq!(bob.invitations()[0].status, InvitationStatus::Pending);
    let alice_two =
        second_device(directory, relay, "+alice", &alice.client.export_identity()).await;
    let before = bob.generation();
    let refused = bob
        .accept_invitation(InvitationId::new([9; 16]), alice_two.address(), 1)
        .await;
    assert!(matches!(refused, Err(GroupError::Policy)), "{refused:?}");
    assert_eq!(bob.invitations()[0].status, InvitationStatus::Pending);
    assert_eq!(bob.generation(), before, "nothing was committed");
}

/// R085: in `revoke_invitation`, the check that the target's route is the target's device is
/// replaced by `false`, so the invitation is revoked before its control fails to reach anyone.
#[tokio::test]
async fn r085_a_revocation_to_a_route_that_is_not_the_targets_device_is_refused() {
    let (directory, relay) = start_server().await;
    let store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &store).await;
    alice.create_group(gid()).unwrap();
    let dave = plain(directory, relay, "+dave").await;
    let dave_member = member_of(&dave);
    alice
        .invite(
            InvitationId::new([9; 16]),
            &dave_member,
            dave.address(),
            100,
            0,
        )
        .await
        .unwrap();
    let dave_two = second_device(directory, relay, "+dave", &dave.export_identity()).await;
    let before = alice.generation();
    let refused = alice
        .revoke_invitation(InvitationId::new([9; 16]), dave_two.address(), 1)
        .await;
    assert!(matches!(refused, Err(GroupError::Policy)), "{refused:?}");
    assert_eq!(alice.invitations()[0].status, InvitationStatus::Pending);
    assert_eq!(alice.generation(), before, "nothing was committed");
}

/// R096: in `install_roster`, `if state.authority != state.local { return Err(Policy) }` is removed.
/// A member that is not the authority is then refused only later, and not at all for a roster that
/// is already installed and an empty list of recipients.
#[tokio::test]
async fn r096_a_member_that_is_not_the_authority_cannot_install_even_the_installed_roster() {
    let (directory, relay) = start_server().await;
    let alice_store = SharedStore::default();
    let mut alice = coordinator(directory, relay, "+alice", &alice_store).await;
    alice.create_group(gid()).unwrap();
    let alice_member = alice.member().unwrap();
    let (mut bob, _bob_store) = joined(directory, relay, "+bob", &alice_member).await;
    let bob_member = bob.member().unwrap();
    let r1 = alice
        .next_roster(vec![alice_member, bob_member.clone()])
        .unwrap();
    alice
        .install_roster(r1, &[(bob_member, route(&bob))], None, 0)
        .await
        .unwrap();
    bob.receive(0).await.unwrap();
    let installed = bob.roster().unwrap().clone();
    let refused = bob.install_roster(installed, &[], None, 0).await;
    assert!(matches!(refused, Err(GroupError::Policy)), "{refused:?}");
}
