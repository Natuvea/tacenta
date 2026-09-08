# 0016 — relay persistence reuses the proven codec and the public API

## Decision

The relay serializes its state — every device queue's log and cursor —
with `Relay::snapshot() -> Vec<u8>`, and rebuilds it with
`Relay::restore(&[u8]) -> Option<Relay>`. A running server exposes the
same via `Server::snapshot()`. Two deliberate constraints:

- **The persisted format reuses the proven wire codec.** A queue's log
  is serialized with `tacenta_wire::encode_stream` — the same stream
  framing proven to round-trip in `spec/Tacenta/Stream.lean`. Only the
  device address and the u64 cursor around it are new bytes, and those
  ride the protocol's existing length-prefix helpers.
- **Restore rebuilds through the public `append`/`ack` API, never a
  back door.** There is no `Session::from_raw_parts` that could install
  a cursor past the log. `restore` enqueues each logged envelope and
  advances the cursor with the ordinary `ack`, so a reconstructed queue
  satisfies the exact invariant (`cursor ≤ log.len`) the delivery
  machine is *proven* to maintain. A snapshot claiming an out-of-range
  cursor is rejected, not forced.

## Considered

- **`#[derive(Serialize/Deserialize)]` on the state types (serde).**
  Would be terser, but `Session` lives in `tacenta-state`, the verified
  crate that Charon/Aeneas translates; adding derives and a serialization
  framework to it risks perturbing the translation and pulls a
  dependency into the proven zone for no gain. Serializing from *outside*
  via the public accessors keeps the verified crate untouched.
- **A raw constructor to rebuild `Session` in one step.** Faster restore,
  but it would let deserialization install a state the proven API cannot
  produce — precisely the invariant-bypass the verification exists to
  forbid. Rebuilding through `append`/`ack` costs a few cycles and keeps
  restore inside the proven envelope.

## Why

Persistence is what separates the running demo from a deployable
service: a restart must not lose queued messages or delivery cursors.
Doing it through the proven codec and the proven API means the feature
adds essentially no new trusted surface — the bytes on disk are framed
by verified code, and the reloaded state is one the verified machine
could have reached on its own. A server persists by writing
`server.snapshot()` to disk on a schedule or at shutdown and coming back
up with `server(Relay::restore(&bytes)?, auth)`.

## What would reopen this

- Scale: a single monolithic snapshot is fine for a small server but
  rewrites everything each save. A real deployment wants incremental
  persistence (append-only log, per-queue records, or a database) — the
  snapshot/restore pair is the semantics that scheme must preserve, not
  the storage engine.
- Crash consistency (atomic replace, fsync, a write-ahead log) is the
  caller's concern today; a durable server needs it addressed.
- Sessions and identities live in the *clients'* stores, not the relay;
  their persistence is a separate matter (the client-side store, still
  no relay involvement).
