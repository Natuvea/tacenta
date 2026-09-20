# 0117 — bounded group live dispatch

## Decision

The live bounded-group sender separates pairwise preparation from relay
dispatch. It authenticates the directory identity against the recipient member
binding, encrypts the recipient's canonical context once, exports the advanced
client provider state, and commits the exact ciphertext plus state through the
outbox preparation boundary. It reserves the committed handoff before placing
those exact ciphertext bytes in a `group` relay envelope. After the relay
accepts, it commits `relay_accepted`; only a transient transport or relay
backpressure result leaves the durable handoff retryable. A permanent relay
refusal freezes the operation rather than misclassifying it as a retry.

Any failure after pairwise encryption but before the preparation snapshot
commits freezes the group operation. It must recover the selected durable
generation before it can retry, never encrypting a new context under that
logical ID.

## Considered

- Reuse direct-message `send` and mark the result as group state afterwards.
- Re-encrypt each retry after a transport error.
- Commit prepared and handed-off records around an exact group envelope.

## Why

The relay only observes opaque ciphertext, while the client needs one durable
fact for each pairwise ratchet movement and retry. The separation preserves
both the group outbox's immutable bytes and the provider's restart state.

## What would reopen this

A transactional provider/store integration can replace the reference
freeze-and-recover boundary only if it preserves exact-ciphertext retries and
the same relay-acceptance rule.
