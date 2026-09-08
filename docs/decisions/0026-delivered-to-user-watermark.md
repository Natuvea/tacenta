# 0026 — delivered-to-user watermark on the relay

## Decision

A client can ask the relay how many messages have been delivered to *all*
of a user's devices — the minimum cursor across them. This is the `User`
machine's `delivered` (proven: the minimum-cursor fold,
`user_delivered_refines`) computed live on the relay's per-device cursors,
so the abstraction that was proven now surfaces as a runtime query.

- **A new relay request, `Delivered { devices }`,** returns
  `DeliveredCount { count }` = the minimum `cursor` over the listed
  devices (0 for an empty list).
- **The caller supplies the device list.** For "how far have all *my*
  devices caught up", the client already knows its own device ids; it need
  not consult the directory. The relay refuses (`Unauthorized`) if any
  listed device is not the authenticated connection's user — the same
  address-comparison authorization as `Poll` / `Ack`, so the relay stays
  blind and needs no directory access.

`tacenta-relay`'s unit test checks the min-cursor and the cross-user
refusal; `tacenta-core`'s `tests/delivered.rs` drives it over a real
socket with authenticated connections: a user with two devices that acked
different amounts reads `min = 1`.

## Considered

- **Answer it in a combined server query over both stores.** "Delivered to
  a user" spanning the *directory* (which devices a user has) and the
  *relay* (their cursors) would put a cross-cutting query in the server and
  make the relay reach into the directory — breaking the blind relay's
  single job. Having the client pass the device list keeps the computation
  on the relay alone, over data it already has (cursors), authorized by
  address comparison alone.
- **A cross-user "is my message delivered to them" receipt.** The natural
  read of "delivered to user" for a *sender* is a delivery receipt about
  the *recipient's* devices — but that leaks the recipient's device sync to
  the sender and needs a privacy/authorization model of its own. This
  decision is scoped to a user's own multi-device watermark (same-user
  only); read receipts are a separate design.
- **Compute the min per logical message.** With independent per-device
  queues (decision record 0011), there is no shared logical message index;
  the watermark is a count of messages acked by every device, which is
  exactly the minimum cursor when messages are fanned to all devices in
  order. That is the model the `User` machine proves; a per-message
  delivered map would be a different, heavier abstraction.

## Why

The `User` machine is proven, and without a query nothing on the networked
path would surface it. Wiring the proven `delivered`
into a relay query connects the machine-checked abstraction to a real
feature (a device knowing its family of devices has caught up) at the
lowest cost — no new store, no directory coupling, the same authorization
the relay already enforces, and the same minimum-cursor semantics the proof
establishes.

## What would reopen this

- **Cross-user delivery receipts.** A sender learning that a message
  reached a recipient's devices is a distinct feature with its own privacy
  model; this watermark is same-user only.
- **The fanned-in-order assumption.** The minimum cursor equals
  "delivered to all" only when every message to the user is fanned to all
  its devices in the same order. A device that receives a direct,
  un-fanned message would make the cursors incomparable; a real client must
  fan uniformly (or the watermark needs a per-message model).
