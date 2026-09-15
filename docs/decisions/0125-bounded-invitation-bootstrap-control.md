# 0125 — bounded invitation bootstrap control

## Decision

The first-profile group envelope gains two product-owned control records before
an invitee can observe a roster it does not yet belong to: an invitation and
its acceptance. An invitation carries one immutable `Invitation` in its
`pending` form and the exact canonical source roster named by that invitation.
An acceptance carries the group ID, invitation ID, source revision, and source
roster digest. Both records are pairwise-authenticated by the existing provider
and are bounded by the group-payload limit.

The authority durably creates the invitation before sending it. The target
accepts only when the pairwise-authenticated sender is the source roster's
authority, the target binding matches the local member, and the source roster
encodes to the invitation's digest. It then durably records
`accepted_pending_admission`; the authority records that status before it sends
control history to the target. A pending or accepted target may observe the
source roster and its authenticated successors, but cannot send or receive an
application context until the authority atomically commits both the successor
that includes it and `admitted { revision }` in the invitation book. Revoked or
expired invitations cannot receive further bootstrap control.

## Considered

- Add every invitee directly to the first roster it receives.
- Let arbitrary pairwise peers receive roster history.
- Carry invitation status outside the durable group-control transcript.
- Use a bounded invitation and acceptance control exchange.

## Why

Roster fan-out alone cannot distinguish an invited observer from an arbitrary
recipient, and treating an observed roster as membership contradicts the
bounded receiver policy. The source roster binds the invitation to one
authority, group, revision, and digest; the durable lifecycle makes an
acceptance and later admission recoverable across a restart. The explicit
records also give the bootstrap path a parser and retention bound instead of
smuggling invitation bytes through application data.

## What would reopen this

A signed replicated membership log or a production group-key protocol may
replace pairwise invitation control. It must still bind the invitee to an
authenticated source epoch, persist acceptance before exposing admission, and
retain bounded replay evidence.
