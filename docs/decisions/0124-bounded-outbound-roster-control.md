# 0124 — bounded outbound roster control

## Decision

An authority sends a roster successor through a bounded durable control outbox.
For each recipient it records the canonical roster payload, exact pairwise
ciphertext, recipient binding, retry reservation, and relay-acceptance result.
The preparation snapshot includes the advanced provider state and the local
roster transition. A restart reuses the stored ciphertext; it cannot encrypt a
new control payload for the same pending handoff.

Control handoffs use the same three-attempt limit as application fan-out. An
unknown publication freezes the operation. A transport failure leaves an exact
committed handoff available for retry; a permanent relay failure freezes it.

## Considered

- Use the direct-message send path for control traffic.
- Persist only the accepted local roster and re-encrypt after restart.
- Keep a bounded control outbox with exact ciphertext recovery.

## Why

Membership changes advance the same pairwise ratchet as application messages.
Publishing local membership without the provider state or retrying with fresh
ciphertext can lose the authenticated control boundary across a crash.

## What would reopen this

A production group protocol may replace pairwise fan-out with signed epoch
distribution, but must keep an explicit durable control-delivery boundary.
