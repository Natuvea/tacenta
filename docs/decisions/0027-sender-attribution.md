# 0027 — sender attribution on delivered messages

## Decision

The relay stamps the authenticated *sender* onto every message it routes,
so a recipient learns who each delivered message is from. The queued unit
becomes `StoredMessage { from: DeviceAddr, envelope: Envelope }`; a `Poll`'s
`Delivered` response carries `Vec<StoredMessage>` instead of bare
envelopes.

- **The sender comes from the authenticated connection, not the payload.**
  When a device sends `Send { to, envelope }`, the relay already knows the
  authenticated sender (the connection's device); it records that as `from`.
  The sender is routing metadata the relay is entitled to see — it does not
  read the envelope payload, which stays opaque.
- **The recipient needs this to decrypt.** Decryption is keyed by the
  sender's address: processing a message — including a first-contact
  PreKey message from a device the recipient has no session with yet —
  requires knowing who sent it. Without attribution, a recipient could only
  decrypt messages from peers it already knew out of band — fixed
  two-party conversations.

## Considered

- **Carry the sender inside the wire `Envelope`.** The `Envelope` is the
  *proven* wire type (`kind`, `payload`); adding a field would change the
  Lean spec and its refinement proof. The sender is relay-level routing
  metadata, not part of the end-to-end envelope, so it belongs in the
  relay's stored unit, around the proven envelope — not inside it.
- **A parallel per-queue sender log.** Keeping the queue as
  `Session<Envelope>` and tracking senders in a second structure would
  duplicate the cursor/ack bookkeeping the generic `Session` already does,
  and risk the two drifting. Storing `Session<StoredMessage>` keeps one
  queue with one cursor; the delivery machine is generic in its element
  type, so its behavior is unchanged.
- **Trust a client-supplied sender field.** The sender could ride in the
  `Send` request, but then a device could forge another's address. Taking
  the sender from the authenticated connection makes it unforgeable at the
  relay: you can only be attributed as the device you authenticated as.

## Why

A relay that cannot tell a recipient who a message is from cannot support a
real client — only a pre-arranged conversation between parties who already
know each other. Attribution is the missing foundation for a general inbox
(receive from anyone, first contact included), and therefore for the client
SDK, groups, and everything downstream. Taking the sender from the
authenticated connection makes it both free (the relay already knows it) and
unforgeable, and keeping it around the proven envelope — not inside it —
leaves the wire codec's proof untouched. The snapshot still rides the proven
envelope encoding per message, wrapped with the sender address, the same way
it already wraps logs with device/cursor headers.

## What would reopen this

- **Sealed sender.** Attribution exposes the sender to the *relay* (which
  already authenticated it) and to the recipient. Hiding the sender from the
  server — Signal's sealed sender — is a distinct, later design; it would
  move attribution into the sealed envelope rather than relay metadata.
- **Spoofing across the crypto boundary.** The relay attributes by
  authenticated connection, but it does not (and cannot) check that the
  ciphertext was actually encrypted by that identity — the recipient's
  session does, on decrypt. The two must agree; a mismatch surfaces
  as a decryption failure, not a relay error.
