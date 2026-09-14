# 0098 — bounded group durable boundary

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

