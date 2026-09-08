# 0011 — ciphertext is queued per device, not per user

## Decision

Received ciphertext is delivered through a **per-device** queue — one
`tacenta_state::Session` (append-only log + acknowledgment cursor) per
device. The multi-device `tacenta_state::User` machine (one shared log,
a cursor per device) is *not* the carrier for ciphertext. It models
logical, user-level delivery accounting; the on-the-wire encrypted
messages live in per-device queues.

The full-stack integration (`tests/delivery_crypto.rs`) necessarily
uses `Session`, not `User`.

## Considered

- **One shared log per user, ciphertext in it (the `User` machine).**
  This is what the shared-log model's shape suggests. It breaks under
  end-to-end encryption: a message to a user is encrypted *separately
  for each device's session*, so there is no single ciphertext to put
  in a shared log — device A's bytes are meaningless to device B. A
  shared log of ciphertext is a category error once E2EE is in play.

## Why

In the Signal model a message fans out to N device sessions and
produces N distinct ciphertexts; the server stores N per-device queues.
The `Session` machine — proven for exactly the properties a queue needs
(no loss, no replay, cursor never rewinds; `docs/claims.md`) — is the
right abstraction for each of those queues. The `User` machine stays
useful, but for the *logical* layer: "delivered to the user" as the
minimum over devices (`delivered`, `isDelivered_iff`) is an accounting
view computed over per-device progress, not a store of bytes.

So the two proven machines have distinct, non-overlapping jobs:
- **`Session`** — a device's ciphertext queue (what the transport
  enqueues and the device drains).
- **`User`** — logical delivery accounting across a user's devices
  (when have *all* devices received message *i*).

The clean-break value: getting this layering right up front, rather
than discovering mid-flight that the shared-log queue can't hold E2EE
ciphertext.

## What would reopen this

- A non-E2EE or server-visible message class (system notices, receipts
  the server originates) could legitimately use a shared log — those
  are not per-device-encrypted. If such a class appears, it gets a
  shared log; encrypted user messages stay per-device.
- Sender-key group messaging changes the fan-out (one ciphertext to a
  group via sender keys) but still lands in each member device's queue,
  so the per-device-queue decision holds.
