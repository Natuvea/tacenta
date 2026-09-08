# 0005 — newly linked devices start at the log tail

## Decision

Linking a device sets its cursor to the current log length: a new
device has nothing pending and receives no history. Specified in
`spec/Tacenta/User.lean` (`linkDevice`), with `delivered_linkDevice`
proving the user-level delivered count is unchanged by linking.

## Considered

- **Start at zero (full backfill).** The new device would owe an ack
  for every message ever logged. In an end-to-end encrypted system the
  device cannot decrypt messages sent before it had keys, so this turns
  the delivery guarantee into a lie: the cursor would advance over
  ciphertext the device can never read, or stall forever at zero and
  drag the user-level delivered count to zero with it — retroactively
  "un-delivering" the user's entire history on every link.
- **Configurable backfill point.** Real flexibility, but it moves a
  security-relevant choice into runtime configuration and multiplies
  the state space the theorems have to cover. Nothing needs it yet.

## Why

Tail-start matches what E2EE can actually promise — history transfer
to a new device, if ever offered, is a separate protocol with its own
keys and its own spec, not a cursor position. It also keeps the
user-level guarantee monotone: `delivered_linkDevice` shows linking is
invisible to delivery, which is exactly the property that makes device
linking safe to offer freely.

## What would reopen this

- A history-transfer feature — that arrives as its own specified
  protocol; the cursor model stays tail-start regardless.
- Receipt semantics that want a distinction between "delivered to all
  current devices" and "delivered to all devices that existed at send
  time" — the latter is what the current model computes; if product
  wants the former, the delivered function (not linking) is what
  changes.
