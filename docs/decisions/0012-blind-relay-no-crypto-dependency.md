# 0012 — the relay is cryptographically blind, enforced by the dep graph

## Decision

`tacenta-relay` — the server component that routes messages between
devices — depends only on `tacenta-wire` (the envelope format) and
`tacenta-state` (the delivery machine). It does **not** depend on
`tacenta-core` or on anything cryptographic.
It routes opaque encrypted envelopes and has no code path to a
plaintext or a key. Server-blindness is therefore not a runtime policy
that could be misconfigured — it is a structural property of the
dependency graph, checkable by reading `Cargo.toml`.

## Considered

- **A single server crate depending on everything** (crypto included),
  with server-blindness maintained by discipline ("just don't decrypt").
  Rejected: it makes the most security-critical property of an E2EE
  system a convention rather than an invariant. A future refactor, a
  well-meaning "let's add read receipts the server computes," or a
  supply-chain issue in a crypto dep could quietly breach it, and
  nothing would catch it.
- **Routing metadata inside the encrypted payload.** Then the server
  could not route at all. The recipient must be server-visible; the
  *content* must not be. So routing (`DeviceAddr`) is passed to the
  relay explicitly, alongside the opaque envelope.

## Why

In an end-to-end encrypted system the server is the adversary you most
want to constrain. Making the relay depend only on the wire and
delivery crates turns "the server cannot read messages" from a promise
into a fact about what code is even linked in. The relay's own routing
key type (`DeviceAddr`) is deliberately distinct from the protocol's
address type in `tacenta-core`, so there is no crypto type in the
relay's surface at all.

A bonus falls out: the relay is thin glue over the *proven* `Session`
machine (one queue per device), so each queue already has the delivery
guarantees — no loss, no replay, a cursor that never rewinds — without
the relay re-proving anything. The relay adds routing; correctness of
the queue is inherited.

## What would reopen this

- Server-originated, non-E2EE message classes (system notices) would be
  produced by a *different* component; they do not belong in the blind
  relay and must not become a reason to give it crypto.
- Sealed sender hides the *sender* from the server too; it changes what
  routing metadata is visible but not the blind-relay principle — the
  relay still routes without reading content.
- A persistent store backend replaces the in-memory queues; it is still
  a store of opaque envelopes, no crypto.
