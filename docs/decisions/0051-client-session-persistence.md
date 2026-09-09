# 0051 — client session persistence: resume the ratchet across a restart

## Decision

`Client::export_state` serializes a client's full resumable state — its
identity secret **and** its live ratchet sessions with every peer it has
an open conversation with — and `connect_with_state` / `sign_in_with_state`
(and their `_tls` siblings) restore it. A process that saves its state,
exits, and restarts resumes each conversation mid-ratchet: a message a
peer sent while the device was down still decrypts.

The blob is `[u32 identity-len][identity][sessions]`, where the identity
half is exactly the existing `export_identity` format (0031) and the
sessions half is, per peer, `[name][device][session]`. The session bytes
are `tacenta-core`'s own session export, which carries the peer's identity
key; this repository does not model or reimplement their contents.

## Context

Decision 0031 persists the *identity* across restarts; with the session
store in memory alone, a restarted client would re-establish every
session from scratch. Re-establishment is silent data loss — a peer that
sent a message to the old session while the client was down encrypted it
to ratchet state the new store does not have, so it can never decrypt
(and, with the poison-tolerance from the reconnection work, is dropped).
For a persistent agent like the echo bot, or any app resumed after being
killed, that would be messages silently lost across every restart.

## Considered

- **Persist only the identity** (status quo, 0031). Keeps the binding and
  avoids a key-fingerprint change, but loses in-flight messages on every
  restart. Kept as `connect_with_identity` for callers that genuinely want
  a fresh store (e.g. a deliberate session reset).
- **A server-side session store.** Wrong layer: sessions carry the private
  ratchet state; putting them on the server would break the end-to-end
  guarantee. Sessions must persist on the *client*.
- **Enumerating the protocol store directly.** Its session map is private.
  The client already tracks which peers it has sessions with (the
  `sessions` set it maintains for send/receive), so `export_sessions` takes
  that peer list and serializes each through the store's public session
  export — no reliance on store internals.

## Why

The client is the only place the ratchet state can live without weakening
the crypto, and the client already knows its peer set, so the export is a
small, honest addition over `tacenta-core`'s public API. Restoring trusted
identities alongside the sessions preserves the trust decisions made when
each session was first established (import does not re-verify — the trust
was earned live, and a restart is not a re-introduction).

Scope and honesty: `export_state` supersedes `export_identity` for callers
that want durability, but both remain. The blob carries session secrets
and an identity private key — the docs state it must be encrypted at rest,
the same bar as `export_identity`. Full **at-rest encryption of the blob**
(a device keystore / OS secure enclave integration) is not in this record;
it is the app's responsibility today and a later platform-bindings
concern.

## What would reopen this

- Multi-device: a device's sessions are its own, but a shared per-user view
  (which devices a peer has) interacts with how state is scoped.
- A server-backed durable client store (unlikely, for the layering reason
  above) or a platform keystore integration that changes the at-rest story.
