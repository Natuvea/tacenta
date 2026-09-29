# 0098 — bounded group durable boundary

> Status (2026-09-29, after 0131 and 0132): the acknowledgement rule below is
> true of a client owned by `GroupClient`, which commits each item's disposition
> before it acknowledges, and which writes every pairwise operation through to
> the snapshot (0132), so restoring the snapshot does not rewind a session. It
> is not true of the plain `Client::receive`, `drain` and `inbound`, which
> acknowledge first and write nothing to a snapshot. An event returned by
> `GroupClient::receive` is committed before it is returned, but a crash between
> that commit and the caller's use of it is not redelivered, and a failed
> acknowledgement drops that call's events (0131).

## Decision

Before a bounded group operation crosses transport, cumulative acknowledgement,
or application-delivery boundaries, the product commits one versioned combined
snapshot. It contains opaque provider state, accepted group/policy state,
immutable logical sends and recipient ciphertexts, invitation records,
inbox/defer/rejection dispositions, dedup state, delivery cursor, and a
monotonic snapshot generation.

A required write result is independently `committed`, `failed`, or
`unknown`. Failed and unknown freeze every affected operation. Recovery selects
one valid durable generation before retrying; it never reconstructs ciphertext,
rewinds pairwise state, or crosses a blocked output boundary from an in-memory
working copy.

Provider state effect and storage result are independent. An advanced or
terminal provider transition is retained with its group disposition even when
that disposition rejects or defers application content. Secure-store counter
advancement, snapshot publication, and directory witness remain distinct
operations; no implementation may claim they are atomically coupled.

Dispatch requires the committed outbound record and its recipient ciphertext.
Application delivery requires the committed inbox disposition and stable event
ID. A cumulative ACK may cover only a fetched prefix whose every item has a
committed accepted, terminal-rejected, or deferred disposition.

## Considered

- Persist provider/session, group, and inbox records independently.
- Treat an unknown write as a failed no-op.
- Use a combined snapshot with explicit recovery outcomes.

## Why

Group fan-out composes pairwise state changes with product membership and
delivery records. A combined reference boundary prevents outputs from describing
state that cannot be recovered. Explicit uncertainty is necessary because a
crash can occur after durable publication but before the caller learns it.

## What would reopen this

Measured production write amplification may replace the reference snapshot with
a journal or database transaction only if it preserves the same outcomes and
recovery rule. This decision does not claim that the current direct-message
client already supplies this atomicity; GC-06 must prove real integration.


## Amendment (0131, 0132, 0134)

The cumulative-acknowledgement rule above is enforced on the live path only
through `GroupClient::receive` (0131). "Never rewinds pairwise state" holds for
direct messages only while a `GroupClient` owns the client, because it writes
provider state through on every pairwise operation (0132). "Failed and unknown
freeze every affected operation" is a latch cleared only by recovery (0134).
Before these records none of the three held on the live client.
