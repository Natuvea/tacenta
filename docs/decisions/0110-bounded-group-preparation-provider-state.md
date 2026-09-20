# 0110 — bounded group preparation retains provider state

## Decision

Every successful bounded group ciphertext preparation publishes the provider
state bytes produced by that exact encryption in the same candidate snapshot
as its `TCGP` record and changed `GroupOutbox` recipient. The provider bytes
replace the prior snapshot value only after the operation store reports
`committed`.

Failed or unknown publication freezes the operation. It neither exposes the
candidate ciphertext nor changes the live outbox or live snapshot, even though
the in-memory provider may already have advanced. The caller must recover the
durable generation before it can retry; it must not re-encrypt the logical
message.

## Considered

- Persist only the ciphertext and assume the pairwise provider can replay it.
- Publish provider state in a separate write after the `TCGP` record.
- Publish provider state, ciphertext, and recipient progress in one snapshot.

## Why

Pairwise encryption advances a ratchet before a group ciphertext may reach the
relay. Retaining only the ciphertext would leave restart state behind the
committed operation and invite key reuse or a fresh ciphertext under the same
logical ID. One snapshot makes the commit boundary cover both state machines.

## What would reopen this

A transactional provider/store integration may replace the opaque byte field,
provided it retains the same exact-before-dispatch recovery rule.
