# 0031 — client identity persistence: export the identity, not the sessions

> Superseded in part by 0051.

## Decision

A client can keep its identity across restarts. `Party::export_identity`
serializes the identity keypair (private half included) and its registration
id; `Party::from_identity` reconstructs a party from that blob with a fresh,
empty session/prekey store. The facade exposes this as
`Client::export_identity` (save the secret) and
`Client::connect_with_identity` (reconnect under it); the original
`Client::connect` keeps its meaning — first-run enrolment with a freshly
generated identity.

What is persisted is the **identity only** — not the session state, and
not the prekeys. On reconnect the client re-publishes a fresh
prekey bundle (a refresh of the existing directory binding, since the
identity key is unchanged) and re-establishes peer sessions lazily on next
use.

## Considered

- **Persist the whole protocol store (identity + sessions + prekeys).** The
  complete picture: a restart would resume live Double Ratchet sessions with
  no re-establishment. But the in-memory protocol store has no
  serialization, so this means either a bespoke encoder over the session
  state or standing up a persistent store implementation of the store
  traits. Larger, and its own slice (decision record 0051) — deferred to
  that, not smuggled in here.
- **Persist nothing; regenerate each connect.** Simple,
  but a returning client presents a new identity key for an address the
  directory already bound to the old one, so trust-on-first-use refuses it —
  the client is locked out of its own address, and any peer who verified it
  sees a key-fingerprint change every restart. Not viable for a real client.
- **A separate `Identity` type instead of a byte blob.** Cleaner typing, but
  more surface for no behavioural gain this slice; the byte blob matches how
  bundles already cross the facade. Revisit if the export grows structure.

## Why

Identity continuity is the property that actually matters for a returning
client: the same bound key means the directory refreshes rather than rejects,
and peers see no key-fingerprint change. Sessions are recoverable without it —
the Double Ratchet re-establishes from a fresh prekey exchange under the same
identity, at the cost of one round of re-establishment, no more. So the
identity is the part worth persisting first, and it is small (one keypair
plus a registration id) and self-contained, where the session store is
larger and its own slice. The test proves
the value by contrast: a saved identity reconnects and keeps talking, while a
fresh identity for the same address is refused with `Rejected`.

The exported blob carries a private key. It is the caller's to store at rest
as carefully as any other secret; the facade names the method `export_*` and
documents the sensitivity rather than pretending it is public material.

## What would reopen this

- **Session persistence lands.** When the durable store work provides a
  serializable protocol store, a restart can resume sessions directly and the
  lazy re-establishment becomes an optimisation, not the only path.
- **The identity export grows structure** (multiple devices, versioned key
  material, an at-rest encryption envelope) — at which point a typed
  `Identity` replaces the raw blob.
- **This is the same plumbing `set_recovery` / `recover` need.** Those
  operations require exporting and re-importing a recovery keypair's private
  half; the keypair serialization added here is the first half of that, so
  they build on this rather than reopening it.
