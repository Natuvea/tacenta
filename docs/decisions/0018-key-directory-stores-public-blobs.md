# 0018 — a key directory of public blobs; clients do the crypto

> Amended by 0074.

## Decision

`tacenta-directory` is a lookup from a device to its published *public*
material: its identity key and its current prekey bundle. Devices
register their material; a peer looks up a bundle to open a session, and
the server looks up an identity key to authenticate a connection.
`tacenta-core` gains `serialize_bundle` / `deserialize_bundle` so a
prekey bundle can travel as bytes (the codec encodes each public field
length-prefixed, like the wire format).

Two constraints, mirroring the relay:

- **The directory holds opaque public blobs and does no cryptography.**
  It stores the identity-key and bundle *bytes* the client produced. The
  server's authenticator deserializes the identity key and verifies
  (crypto stays in the crypto layer); a peer deserializes the bundle and
  opens the session. The directory never parses a key or touches a
  secret — it depends only on `tacenta-relay` for the `DeviceAddr` key.
- **Nothing here is secret.** Identity *public* keys, prekey *public*
  keys, signatures — all published-by-design. No private key, no
  plaintext, ever enters the directory.

Together with the relay (routes opaque ciphertext, blind) the server now
has two blind stores: one of messages, one of public keys.

## Considered

- **Store parsed protocol types** (the identity key and prekey bundle)
  in the directory. Would pull `tacenta-core` into the directory crate
  for no gain — the directory does not need to understand the material
  to store and serve it. Storing bytes keeps the crate a dependency-light,
  crypto-free store, and the (de)serialization lives once, in the crypto
  layer that owns those types.
- **Fold the directory into the relay.** They are both "server," but the
  relay's whole identity is being blind to *message* content; a key
  directory is a different service with a different shape (lookup, not
  queues). Keeping them separate keeps each crate's job single.

## Why

Without a directory, key exchange is out of band: one party's bundle
would have to be handed directly to the other. A real messenger needs a
place to publish and find keys, and the directory removes that
out-of-band step — the demo has each party *register* identity and
bundle, the server authenticate *against the directory*, and the sender
*look up* the recipient's bundle before opening a session. Keeping the directory to
opaque public blobs means the feature adds a store, not a new trusted
crypto surface: the bytes are produced and consumed by the crypto layer,
and the directory is as blind to their meaning as the relay is to a
ciphertext.

## What would reopen this

- **Registration trust** — who may claim a given device identity — is
  addressed by proof of possession plus trust on first use (decision
  record 0019), with authorized key-continuity rotation on top (decision
  record 0024). What remains is lost-key recovery
  (no old key to sign the rotation).
- A networked directory *service* (register/lookup over a transport,
  persistent storage) is the next step; the in-memory `Directory` is the
  data model that service will wrap, exactly as the transport wraps the
  relay.
- Multi-device fan-out (`devices_of`) is now used by a sender
  (`tests/multi_device.rs`): a message to a user is encrypted per device
  and sent to each device's queue. Still client-side and demonstrated in
  a test, not yet the demo; the "delivered once all devices ack"
  accounting the `User` machine models is not yet wired into the live
  path.
