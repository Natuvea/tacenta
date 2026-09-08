# 0015 — device authentication: enforce blind, verify with injected crypto

## Decision

A connection authenticates as one device before it may act. The work is
split across three layers so each keeps its established property:

- **Relay (blind).** Enforces authorization by *address comparison
  only*: a `Poll` or `Ack` may touch only the authenticated device's own
  queue, otherwise `Unauthorized`; `Send` may target anyone. No crypto
  (decision 0012 intact).
- **Transport (crypto-free).** Runs the handshake *protocol* — send a
  challenge, receive `encode_auth(device, signature)`, accept or reject —
  but delegates the actual signature check to an injected `Authenticator`
  trait. No crypto dependency (decision 0014 intact).
- **Application (`Authenticator` impl).** Owns the crypto: an
  unpredictable challenge, and verifying the device's signature over it
  against the device's registered public identity key. In the test this
  is a directory of identity keys, verified through `tacenta-core`.

A client proves it is a device by signing the server's challenge with
that device's **identity private key** (`Party::sign_challenge`); the
server verifies against the **public identity key** it holds for that
device.

## Considered

- **One component doing auth + routing + crypto.** Simplest to write,
  but it collapses the blind-relay and crypto-free-transport invariants
  that the layering exists to guarantee. The most security-sensitive
  check in the system would then depend on convention, not structure.
- **Bearer tokens / passwords.** Weaker and require server-side secrets.
  Signing a fresh challenge with the identity key the device already
  owns proves possession without the server storing anything secret —
  only public keys — and reuses the identity already central to the
  E2EE story.
- **Authenticating `Send` too (proving who a message is from).** The
  recipient already authenticates the sender cryptographically through
  the Signal session; a server-side sender check would be redundant for
  integrity and is really an anti-abuse concern, deferred.

## Why

The split keeps every earlier decision true while ensuring no client
can poll another device's queue. Enforcement is pure address
comparison, so the relay stays blind and the check is trivially
auditable. Verification is injected, so the transport stays a byte
mover. The crypto lives in one small application-level component with a
clear job: challenge, and verify a signature against a registered key.
The capstone test (`e2ee_conversation_over_real_sockets`) runs the
full flow — both clients sign the server's challenge with their identity
keys, are verified against a directory, and only then converse — and a
transport test shows a bad signature is rejected at the handshake, and
the relay refuses a cross-device `Poll`.

## What would reopen this

- The identity-key directory (who is registered for which device) is a
  real service — registration, key-change handling, revocation — treated
  here as an out-of-band map. That service is its own design.
- Session resumption / tokens to avoid re-signing per connection would
  layer on top of this challenge-response, not replace it.
- Sealed sender changes what the server learns about senders; it does
  not change device authentication of the *connection*.
