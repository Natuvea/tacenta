# 0108 — bounded group outbox-owned recipient progress

## Decision

After `TCGI` creates a logical send, all recipient preparation and handoff
operations address that committed logical ID inside `GroupOutbox`. They mutate
a candidate outbox record, write the corresponding `TCGP` or `TCGH` snapshot
entry, and replace the live outbox only after the snapshot commits. Callers do
not prepare or reserve a detached copy of a logical send after its intent has
entered the outbox.

An unknown or failed write leaves the live outbox recipient disposition,
ciphertext, commitment, and attempt count unchanged. A missing logical ID is a
policy error and cannot synthesize a new record at a later stage.

## Considered

- Keep logical intent and mutable recipient progress in separate values.
- Reconstruct a send from snapshot entries during each retry.
- Use the committed outbox record as the sole progress owner.

## Why

One durable owner prevents a recovery path from preparing bytes under an intent
that differs from the record it will later reserve and dispatch.

## What would reopen this

A journaled production store may split records physically, provided its
transaction and recovery semantics still expose one authoritative logical send.
