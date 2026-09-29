//! Rules of `InvitationBook` and `Invitation` (`crates/tacenta-group/src/invitation.rs`): an
//! expired invitation cannot be revoked, a bootstrap is only made for a pending invitation, and an
//! invitation with an unsupported policy version is refused.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made. It uses only the public API of `tacenta-group`.
//!
//! - M163 (`invitation.rs:643`): `InvitationBook::revoke` returns the record of an `Expired`
//!   invitation.
//! - M168 (`invitation.rs:133`): `InvitationBootstrap::new` no longer requires the invitation to be
//!   `Pending`.
//! - M170 (`invitation.rs:343`): `Invitation::new` accepts an unsupported policy version.
//!
//! The ids (`M###`, `D##`) are those of the single-change mutation run against 97689a0; the
//! `file:line` in each test's doc comment is the change site at that commit.

use tacenta_group::*;

fn group() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}

fn named(name: &str) -> Member {
    Member::new(name.as_bytes().to_vec(), vec![1])
}

fn alice() -> Member {
    named("alice")
}

fn bob() -> Member {
    named("bob")
}

const DIGEST: [u8; DIGEST_LEN] = [1; DIGEST_LEN];

fn invitation(id: u8, target: Member, expires_at: u64) -> Invitation {
    Invitation::new(
        InvitationId::new([id; 16]),
        group(),
        target,
        0,
        DIGEST,
        POLICY_VERSION_V1,
        expires_at,
    )
    .unwrap()
}

/// A book holding invitation 7 for Bob, expiring at 10, created at time 0.
fn book_with_one() -> InvitationBook {
    let mut book = InvitationBook::new(group());
    book.create(&alice(), &alice(), &[alice()], invitation(7, bob(), 10), 0)
        .unwrap();
    book
}

fn id7() -> InvitationId {
    InvitationId::new([7; 16])
}

/// M163 (`invitation.rs:643`): `revoke` of an Expired invitation returns the record instead of
/// Expired.
#[test]
fn m163_an_expired_invitation_cannot_be_revoked() {
    let mut book = book_with_one();
    assert_eq!(
        book.revoke(id7(), &alice(), &alice(), 10).err(),
        Some(Error::Expired)
    );
}

/// M168 (`invitation.rs:133`): `InvitationBootstrap::new` no longer requires a Pending invitation.
#[test]
fn m168_a_bootstrap_is_only_made_for_a_pending_invitation() {
    let genesis = Roster::new(
        group(),
        0,
        [0; DIGEST_LEN],
        alice(),
        POLICY_VERSION_V1,
        false,
        vec![alice()],
    )
    .unwrap();
    let mut book = book_with_one();
    assert!(InvitationBootstrap::new(book.records()[0].clone(), genesis.clone()).is_ok());
    book.accept(id7(), &bob(), 0, &DIGEST, 1).unwrap();
    assert_eq!(
        InvitationBootstrap::new(book.records()[0].clone(), genesis).err(),
        Some(Error::Conflict)
    );
}

/// M170 (`invitation.rs:343`): `Invitation::new` accepts an unsupported policy version.
#[test]
fn m170_an_invitation_with_an_unsupported_policy_is_refused() {
    assert_eq!(
        Invitation::new(InvitationId::new([7; 16]), group(), bob(), 0, DIGEST, 2, 10).err(),
        Some(Error::UnsupportedPolicy)
    );
}
