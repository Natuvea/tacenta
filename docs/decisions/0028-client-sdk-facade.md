# 0028 — the client SDK facade

## Decision

`tacenta-client` is a high-level `Client` that wraps everything a caller
would otherwise orchestrate by hand — an identity and its protocol store,
a directory connection, an authenticated relay connection, and per-peer
sessions — behind three calls:

- **`Client::connect(&Config)`** — generate an identity, publish it to the
  directory, and authenticate to the relay; returns a client ready to use.
- **`client.send(to, message)`** — open a session on first contact (a
  directory lookup of the recipient's bundle) if needed, encrypt, and route.
- **`client.receive()`** — await the next inbound mail, then decrypt and
  acknowledge every pending message, returning each as `Received { from,
  plaintext }`.

This is the surface the platform bindings (UniFFI / wasm) will export. It
turns the ~200-line orchestration the demo performs into a handful of calls,
and it is what makes example apps possible.

## Naming

No stuttering — never a namespace and its member sharing a word (no
`client.chat.chat`, no `Message::message`). Verb methods on the handle
(`send` / `receive` / `connect`), plain nouns for data (`Config`,
`Received`), unprefixed type names inside the crate (`tacenta_client::Client`,
not `TacentaClient`). Each path segment reads distinct from its neighbour.

## Considered

- **Extend `tacenta-core` instead of a new crate.** The facade needs the
  transport, relay, and directory as real dependencies; folding those into
  the crypto crate would make the client engine depend on the whole stack.
  A separate `tacenta-client` over core + transport + relay + directory
  keeps `tacenta-core` the crypto engine and gives the bindings one crate to
  target.
- **Separate enrolment from connection.** `connect` currently both
  registers (an enrolment step) and authenticates (a per-session step), and
  generates a fresh identity each time. A real client persists its identity
  and registers once; splitting `enrol` from `connect` and adding an
  identity-restore path is the natural next step, deferred to keep the first
  facade small.
- **Track sessions in the store vs. in the client.** The client keeps a
  `HashSet` of peers it has a session with, updated on both `send` (after
  establishing) and `receive` (after a decrypt establishes one), so it does
  not re-establish and reset a live session. Querying the store would also
  work; the set is simpler and sufficient while the store is per-connection.

## Why

The core is complete but low-level — using it means driving `Party`,
`DirConnection`, `Connection`, the wire protocols, and session setup by
hand. Nothing downstream (bindings, example apps, real use) can happen until
that is wrapped in an ergonomic API, and the API is the thing every binding
exports, so it is the highest-leverage next slice. Sender attribution
(decision record 0027) is what made a general `receive` possible — the
client's `tests/conversation.rs` sends a first-contact message that the
recipient decrypts and attributes without any prior knowledge of the sender.

## What would reopen this

- **Persistent identity and enrolment.** A real client stores its identity
  and prekeys and registers once, not per connect. That needs a durable
  store behind `Party` (the crypto store is in-memory today) and an
  enrol/restore split on the facade.
- **Reconnection and backlog drain.** `receive` awaits a push; messages that
  arrived while disconnected need a poll-on-connect drain, and a dropped
  connection needs reconnect-and-resume. Neither is handled yet.
- **The trust operations.** `rotate` / `set_recovery` / `recover` and the
  delivered-to-user watermark exist on the wire but are not yet on the
  `Client`; they are natural additions once the send/receive core is in use.
