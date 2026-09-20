# 0100 — bounded group roster progression

## Decision

`RosterView` owns the accepted roster for one bounded group. Genesis is an
authenticated authority roster at revision zero with the all-zero predecessor
digest and exactly that authority as its one active member. The supplied digest
must be the standalone-core roster commitment of the roster's exact canonical
preimage; the product integration computes it through the core adapter before
calling this policy layer.

An authenticated successor has the same group ID, authority binding, and policy
version, is exactly one revision newer, and names the accepted digest as its
predecessor. It may close a group but may not reopen one. A stale revision,
missing predecessor, changed authority, changed policy, changed same-revision
value, or unauthenticated authority is refused without changing the accepted
view. Repeating the exact accepted roster and digest is a duplicate.

An observer has no application membership until its local `RosterView` accepts
a roster that contains its complete identity/device binding. Invitation status
remains a separate target-side record: acceptance of an invitation cannot make
the observer active, while an accepted authority successor can be used to admit
the corresponding invitation.

## Considered

- Treat any newer roster from a trusted pairwise peer as current.
- Allow the roster authority or policy to change in place.
- Make invitation acceptance activate application membership.
- Require one authenticated, predecessor-bound successor at a time.

## Why

The bounded validation trace needs an observable r0/r1/r2 history where C can
observe r1 without being a member, then become active at r2. Keeping the
authority, digest, and predecessor checks in one state transition prevents an
accepted roster from being silently replaced by routing or invitation state.

## What would reopen this

Authority transfer, multi-device membership, or detached-control signatures
requires a new authenticated control protocol and a versioned successor.
