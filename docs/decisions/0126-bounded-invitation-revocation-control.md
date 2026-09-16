# 0126 — bounded invitation revocation control

## Decision

The first-profile group envelope gains an authority-to-target invitation
revocation control. Its canonical payload binds the group ID, invitation ID,
source revision, and source-roster digest already fixed by the invitation. The
pairwise provider authenticates the authority; the payload adds no new
membership authority or detached signature.

The authority changes its durable invitation book to `revoked` before it sends
the exact prepared control. A target accepts the control only when its decoded
bootstrap record has the same immutable fields and its pinned source roster
names the authenticated peer as authority. It persists the provider state and
the `revoked` invitation-book state in one operation snapshot before exposing
the result. Repeating the same control returns the durable revoked state.

Revocation is terminal for a pending or accepted invitation. It does not remove
an admitted member: removal remains an authenticated roster successor. A
revoked target receives no later successor-history or admission control, even
if an older prepared handoff is recovered. The authority checkpoints the
terminal invitation state and cancellation of that target's earlier
non-revocation controls together, retaining the exact ciphertext as evidence
but refusing first dispatch and retry. A retried revocation instead reuses its
already committed exact handoff.

## Considered

- Leave revocation as an authority-local bookkeeping transition.
- Treat a roster that omits a target as revocation in every lifecycle state.
- Send an unbound pairwise text notice.
- Add one bounded, provider-authenticated revocation control.

## Why

The invitee needs a durable, attributable terminal state before it can stop
accepting control history. Binding the original source tuple prevents an
authority control for a different invitation or source epoch from revoking the
record. Keeping removal separate preserves the distinction between a pending
observer and an active member.

## What would reopen this

A replicated signed membership log or production group-key protocol may replace
this control. It must retain an authenticated terminal invitation disposition,
bind it to its source epoch, and preserve the prepare-before-dispatch boundary.
