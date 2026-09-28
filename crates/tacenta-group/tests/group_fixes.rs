//! Regression tests for the cold-read findings CR-06 and CR-12 (decisions
//! 0127 to 0130). Each test fails on the code at 75c9a20 and passes after the
//! fix; the git history of this file and of `src/` shows both states. They use
//! only the public API of `tacenta-group`.

use tacenta_group::*;

fn group() -> GroupId {
    GroupId::new(*b"bounded-group-id")
}

fn mk(identity: &[u8], device: &[u8]) -> Member {
    Member::new(identity.to_vec(), device.to_vec())
}

fn roster_at(revision: u64, authority: Member, closed: bool, members: Vec<Member>) -> Roster {
    Roster::new(
        group(),
        revision,
        [0; DIGEST_LEN],
        authority,
        POLICY_VERSION_V1,
        closed,
        members,
    )
    .unwrap()
}

fn try_roster(authority: Member, members: Vec<Member>) -> Result<Roster, Error> {
    Roster::new(
        group(),
        1,
        [0; DIGEST_LEN],
        authority,
        POLICY_VERSION_V1,
        false,
        members,
    )
}

// ---------------------------------------------------------------------------
// CR-12 (a): roster order is the (identity, device) pair (decision 0127)
// ---------------------------------------------------------------------------

#[test]
fn roster_order_is_the_identity_device_pair_not_the_concatenation() {
    // As pairs, ("a", [ff]) < ("ab", []) because "a" is a proper prefix of
    // "ab". As concatenations, "a\xff" > "ab".
    let first = mk(b"a", &[0xff]);
    let second = mk(b"ab", &[]);
    assert!(try_roster(first.clone(), vec![first.clone(), second.clone()]).is_ok());
    assert_eq!(
        try_roster(first.clone(), vec![second, first]),
        Err(Error::NonCanonical)
    );
}

#[test]
fn members_with_equal_concatenations_share_a_roster_in_pair_order() {
    // ("a", "bc") and ("ab", "c") both concatenate to "abc". They are two
    // distinct members and must be able to share a roster, in pair order.
    let first = mk(b"a", b"bc");
    let second = mk(b"ab", b"c");
    assert!(try_roster(first.clone(), vec![first.clone(), second.clone()]).is_ok());
    assert_eq!(
        try_roster(first.clone(), vec![second, first]),
        Err(Error::NonCanonical)
    );
}

#[test]
fn recipient_order_follows_the_same_pair_order() {
    let prefixed = mk(b"a", &[0xff]);
    let longer = mk(b"ab", &[]);
    let sender = mk(b"b", &[1]);
    let roster = roster_at(
        1,
        sender.clone(),
        false,
        vec![prefixed.clone(), longer.clone(), sender.clone()],
    );
    let send = |recipients: Vec<Member>| {
        LogicalSend::new(
            &roster,
            [9; DIGEST_LEN],
            sender.clone(),
            0,
            recipients,
            b"hi".to_vec(),
        )
    };
    let in_order = send(vec![prefixed.clone(), longer.clone()]).unwrap();
    assert_eq!(
        send(vec![longer.clone(), prefixed.clone()]).map(|_| ()),
        Err(Error::NonCanonical)
    );
    // Recovery applies the same rule to the immutable intent.
    let intent = in_order.encode_intent().unwrap();
    assert_eq!(LogicalSend::decode_intent(&intent), Ok(in_order));
}
