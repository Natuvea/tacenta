# 0111 — bounded group intent recovery codec

## Decision

The durable `TCGI` record is recovered by decoding the exact canonical
logical-intent preimage defined in decision 0105. Recovery validates the fixed
group ID and digest widths, member byte bounds, reserved revision, payload
bound, nonempty bounded recipient list, full-binding ordering, and per-identity
uniqueness before it creates any mutable recipient progress.

The resulting logical send always begins with every recipient `pending`.
Later transcript records may advance that recovered record only when their
canonical application context reproduces the immutable intent. A malformed or
noncanonical intent produces no recoverable send.

## Considered

- Reconstruct intent from debug fields or the most recent ciphertext record.
- Deserialize a private Rust structure without validating its fields.
- Decode and validate the canonical logical-intent grammar first.

## Why

The immutable intent is the root of every prepared ciphertext and retry. A
recovery path that accepts a different recipient set, payload, or binding could
turn durable progress into a new logical operation after a restart.

## What would reopen this

A successor logical-ID or multi-device profile needs a versioned successor
intent grammar and a migration rule; it cannot silently reinterpret this
preimage.
