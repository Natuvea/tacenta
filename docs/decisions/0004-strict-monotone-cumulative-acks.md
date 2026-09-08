# 0004 — acks are cumulative, strictly monotone, and reject-or-apply

## Decision

A device acknowledges delivery with a single cumulative cursor value
("everything up to `n`"). An ack is accepted only if it strictly
advances the cursor and does not exceed the log; anything else is
rejected outright and leaves the state untouched. No clamping, no
partial application. Specified in `spec/Tacenta/Session.lean`
(`ack?`, with `ack?_rejects` pinning the rejection cases).

## Considered

- **Per-message acks.** Finer-grained, but forces the server to track
  arbitrary delivered-sets per device; gaps in the set are exactly the
  states the delivery guarantees are supposed to exclude.
- **Clamping invalid acks** (e.g. treating an over-long ack as "ack
  everything", or an equal ack as a harmless no-op success). Friendlier
  to sloppy clients, but it makes the accepted-ack postcondition
  conditional — "the cursor is now `n`, unless it was clamped" — which
  weakens every theorem downstream and hides client bugs that should
  surface.

## Why

Cumulative cursors make the delivery guarantee one number per device,
and the strict reject-or-apply rule keeps the state machine's contract
unconditional: a successful ack means exactly "the cursor moved to `n`
and nothing else changed" (`pending_ack?`), and a rejected ack means
exactly nothing happened. Unconditional postconditions are what keep
the proofs small now and the Aeneas translation tractable later. An
ack beyond the log is a protocol violation by the peer, and surfacing
it beats absorbing it.

## What would reopen this

- Multi-device fan-out design (one log, several cursors) — expected to
  compose without changing per-cursor semantics, but the model grows.
- A transport that can reorder or replay acks in flight would need
  idempotent re-acks (`n = cursor` as success); that is a deliberate
  weakening and gets its own record if it happens.
