# 0095 — bounded group logical sends and retries

## Decision

A bounded group logical send is an immutable product record keyed by
`(group_id, revision, sender_identity, sender_device, sequence)`. Sequence is
a monotonically increasing unsigned 64-bit counter allocated with the record,
never derived from a pairwise ratchet, never reused, and reset only in a new
revision namespace. The record fixes the roster digest, payload bytes, the
pinned core payload commitment over the canonical application context, and the
complete canonical recipient set before any pairwise operation or transport
handoff.

Each recipient has its own immutable ciphertext and disposition:
`pending`, `prepared`, `handed_off`, `relay_accepted`, `cancelled`, or
`exhausted_unknown`. No disposition means recipient application delivery.
A conflicting record under the same logical ID is refused; an exact duplicate
returns the committed record.

Before each transport handoff, the product durably reserves one of at most
three attempts for that recipient's exact ciphertext. A crash may consume a
reserved attempt. A retry reuses the stored ciphertext and does not re-encrypt,
roll back pairwise state, or reconstruct recipients from a newer roster.
Relay acceptance, cancellation, and attempt exhaustion stop automatic retry.
Exhaustion records `exhausted_unknown`, never a nondelivery conclusion.

A newly accepted removal cancels obsolete unsent recipient work and retries,
while retaining prior handoff evidence and consumed pairwise state. Work
already ordered before the local removal update remains handed off; it is not
rewritten as cancelled.

## Considered

- Treat a fan-out send as one delivered-to-everyone result.
- Re-encrypt on retry.
- Recompute recipients after a membership change.
- Persist one immutable logical record with per-recipient progress.

## Why

A fan-out can partially succeed. Immutable per-recipient state gives recovery
a truthful status without key reuse or recipient substitution. Separating relay
acceptance from application acceptance keeps the protocol from making a delivery
claim it cannot observe.

## What would reopen this

A production multi-device profile, sender-key distribution, a changed retry
budget, or a different durable transaction model requires a versioned successor.
This record defines no transport API and does not make the current client
durable; GC-05/06 integrate the real provider and store.
