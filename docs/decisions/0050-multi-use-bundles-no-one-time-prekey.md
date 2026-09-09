# 0050 — bundles are multi-use: no one-time prekey until the directory can dispense one

> Superseded by 0074.

## Decision

`Party::publish_bundle` publishes a bundle with **no one-time EC
prekey** — identity, signed prekey, and ML-KEM prekey only. The directory
stores one bundle blob per device and serves the same copy to every
peer (decision 0018), so everything in the bundle must be multi-use.

## Context

A one-time prekey embedded in a stored bundle is consumed when the first
peer's first message is decrypted; every *later* first contact against
the same served copy would then reference a prekey the recipient no
longer holds — `InvalidPreKeyId` at decrypt. A long-lived recipient such
as the shared echo bot meets a second fresh peer routinely, so a
served-many-times bundle must carry no single-use material.

## Considered

- **Dispensing one-time prekeys from the directory** (a pool per device, each lookup pops one, bundle-without-prekey as the
  exhausted fallback). Correct, and where this ends up — but it
  changes the directory from "stores public blobs" (0018) to a stateful
  dispenser, touches the wire protocol, and deserves its own record.
- **Republishing a fresh bundle after each consumed first contact.**
  Racy (two first contacts between republishes still die), and it turns
  every first contact into a directory write.
- **Serving the same one-time prekey to everyone.** Guaranteed
  `InvalidPreKeyId` for the second first-contact.

## Why

The signed prekey and the ML-KEM prekey are multi-use by design, so a
served-many-times bundle composed of only those is sound — verified
by `both_sides_agree_without_one_time_prekey` (initiator and responder
derive the same secret when the bundle carries no one-time prekey,
only the signed and reusable KEM keys). PQXDH's
post-quantum contribution is preserved: the ML-KEM prekey still feeds
the handshake (the spec's `pqxdh_agree` covers the no-one-time-prekey
case explicitly).

The trade-off, stated honestly: without a one-time prekey, the X3DH/
PQXDH first-message forward-secrecy contribution that the one-time
prekey provides is absent — compromise of the recipient's signed-prekey
and identity private keys could expose *initial* messages that a
one-time prekey would have protected. The Double Ratchet takes over
immediately after session establishment, restoring forward secrecy from
the first reply onward. This matches the protocol's own defined
behavior when a directory has run out of one-time prekeys; we are
permanently in that (specified, analyzed) state until dispensing lands.

## What would reopen this

- The directory learns to dispense one-time prekeys individually
  (decision record 0074). Bundles then carry them again, and this record
  retires.
