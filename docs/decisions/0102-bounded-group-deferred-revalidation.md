# 0102 — bounded group deferred revalidation

## Decision

`GroupReceiver` retains the full canonical application context and commitment
for each bounded future item. After a roster has already been accepted by the
roster-control layer, the integration installs that roster into the receiver.
The receiver reprocesses each deferred item against the new current roster,
digest, sender binding, local recipient binding, and revision before creating
an accepted event.

An item that matches the new revision is accepted only through the ordinary
current-message checks. One that remains within the future window is retained
only if both bindings remain active. A newly stale, invalid-digest, removed, or
out-of-range item becomes a terminal refusal. The returned dispositions must
be committed with the roster transition before ACK or application delivery.

## Considered

- Promote deferred items automatically at a matching revision.
- Store only a dedup key for future items.
- Revalidate the complete original context after roster acceptance.

## Why

A future item was authorised against an older membership view. Its sender or
recipient can change before the relevant roster arrives, so a revision match
alone cannot establish an application effect.

## What would reopen this

A production control-sync format may change how deferred records are stored,
but it must retain enough authenticated context to repeat these checks.
