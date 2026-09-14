# 0101 — bounded group roster cancellation

## Decision

When the local client accepts a newer roster, it stops every incomplete
logical-send recipient record from an older revision of that group. Pending and
prepared records become `cancelled`. A record already handed to transport
becomes `cancelled-after-handoff`: it retains its immutable ciphertext,
commitment, attempt count, and handoff evidence, but no further automatic retry
may reserve or dispatch it. A relay-accepted record retains its final relay
observation and is not relabelled as delivery.

The roster acceptance, changed fan-out records, and snapshot generation are a
single candidate durable update. If the update is failed or unknown, the live
roster and all logical sends remain unchanged and no cancellation claim is
returned.

## Considered

- Cancel only removed members' queued records.
- Delete handed-off ciphertext after a roster change.
- Keep retrying old-revision ciphertext until relay acceptance.
- Retain evidence while blocking all old-revision incomplete work.

## Why

A receiver that accepts a newer roster refuses older application context.
Continuing local retries after that point wastes ratchet state and could make
the sender report activity for a message that cannot be accepted. Handoff is
not reversible, so its evidence remains durable even though later retries stop.

## What would reopen this

A production retransmission or delivery-receipt protocol may need a distinct
reconciliation state, provided it never makes a superseded application context
eligible for a fresh retry.
