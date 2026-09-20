# 0106 — bounded group handoff reservation

## Decision

Before dispatching a prepared group ciphertext, the client records a `TCGH`
outbox entry containing the canonical application context, its core payload
commitment, the exact stored ciphertext, and the recipient's reserved attempt
number and disposition. The candidate logical send and snapshot commit together
before the coordinator returns the ciphertext record to transport.

An attempt reservation advances only the fixed ciphertext record. The third
reservation enters `exhausted_unknown`; no fourth reservation or fresh
encryption is allowed. Failed or unknown snapshot publication freezes the
operation and leaves the live recipient progress unchanged. Relay acceptance is
recorded separately and is not a recipient application receipt.

## Considered

- Dispatch then remember the attempt.
- Regenerate ciphertext on retry.
- Commit the exact prepared record and reservation before handoff.

## Why

The crash boundary between pairwise preparation and relay handoff must not let
a restart repeat a ratchet step or claim an unrecorded attempt. The explicit
unknown terminal state remains truthful when delivery cannot be observed.

## What would reopen this

A production transport receipt or different retry budget requires a versioned
successor that still commits bytes and retry state before dispatch.
