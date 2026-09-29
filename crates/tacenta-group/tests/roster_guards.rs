//! Guards of `Roster` and `RosterView` (`crates/tacenta-group/src/lib.rs`,
//! `crates/tacenta-group/src/roster_view.rs`): the genesis roster has no predecessor, the accepted
//! roster offered again under another digest is a conflict, and a checkpoint that omits the pinned
//! authority is refused.
//!
//! Each test passes on the code as it stands and fails when the one change named in its doc comment
//! is made. It uses only the public API of `tacenta-group`.
//!
//! - M156 (`roster_view.rs:206`): `accept_successor` compares only the roster, not its digest.
//! - M157 (`roster_view.rs:161`): `RosterView::decode_state` does not require the authority among
//!   the checkpoint's members.
//! - M173 (`lib.rs:294`): `Roster::validate` accepts a genesis roster with a non-zero predecessor
//!   digest.
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

fn commit(bytes: &[u8]) -> [u8; DIGEST_LEN] {
    let mut digest = [0u8; DIGEST_LEN];
    for (index, byte) in bytes.iter().enumerate() {
        digest[index % DIGEST_LEN] ^= byte;
    }
    digest
}

fn genesis() -> Roster {
    Roster::new(
        group(),
        0,
        [0; DIGEST_LEN],
        named("alice"),
        POLICY_VERSION_V1,
        false,
        vec![named("alice")],
    )
    .unwrap()
}

/// M156 (`roster_view.rs:206`): in `accept_successor`, `candidate == self.roster && digest ==
/// self.digest` becomes `candidate == self.roster`, so the accepted roster offered again under a
/// different digest is reported `Duplicate` instead of `Conflict`.
#[test]
fn m156_the_accepted_roster_under_another_digest_is_a_conflict() {
    let genesis = genesis();
    let digest = commit(&genesis.encode().unwrap());
    let mut view = RosterView::accept_genesis(&named("alice"), genesis.clone(), digest).unwrap();
    assert_eq!(
        view.accept_successor(&named("alice"), genesis.clone(), digest),
        RosterDisposition::Duplicate
    );
    assert_eq!(
        view.accept_successor(&named("alice"), genesis, [9; DIGEST_LEN]),
        RosterDisposition::Rejected(RosterRefusal::Conflict)
    );
}

/// M157 (`roster_view.rs:161`): in `RosterView::decode_state`, the check that the checkpoint's
/// members include the pinned authority (for a revision above zero) is removed.
#[test]
fn m157_a_checkpoint_that_omits_the_authority_is_refused() {
    // Revision one with Bob alone: well formed as a roster, but the authority
    // (Alice) is not a member, which `accept_successor` would never have accepted.
    let roster = Roster::new(
        group(),
        1,
        [0; DIGEST_LEN],
        named("alice"),
        POLICY_VERSION_V1,
        false,
        vec![named("bob")],
    )
    .unwrap();
    let roster_bytes = roster.encode().unwrap();
    let mut state = b"Tacenta Group Roster View State v1".to_vec();
    state.extend_from_slice(&(roster_bytes.len() as u32).to_be_bytes());
    state.extend_from_slice(&roster_bytes);
    state.extend_from_slice(&commit(&roster_bytes));
    assert_eq!(
        RosterView::decode_state(&state, &named("alice"), commit).err(),
        Some(RosterRefusal::MissingAuthorityMember)
    );
}

fn alice() -> Member {
    Member::new(b"alice".to_vec(), vec![1])
}

/// M173 (`lib.rs:294`): in `Roster::validate`, `self.predecessor_digest != [0; DIGEST_LEN]` is
/// removed from the revision-zero condition, so `Roster::new` accepts a genesis roster with a
/// non-zero predecessor digest (`RosterView::accept_genesis` still refuses it; the roster type did
/// not).
#[test]
fn m173_a_genesis_roster_has_no_predecessor() {
    assert_eq!(
        Roster::new(
            group(),
            0,
            [1; DIGEST_LEN],
            alice(),
            POLICY_VERSION_V1,
            false,
            vec![alice()]
        )
        .err(),
        Some(Error::InvalidGenesis)
    );
}
