# 0020 — the directory as a networked service, alongside the relay

## Decision

The in-memory `Directory` (decision record 0018) now has a socket service
in front of it, built the same way the transport wraps the relay
(decision record 0014): a crypto-free request/response protocol in the
directory crate (`DirRequest` / `DirResponse` with a length-prefixed
codec), and a `serve_directory` / `DirConnection` pair in the transport.

- **Two operations.** `Register { device, identity, bundle, signature }`
  and `Lookup { device }`. Registration carries the proof-of-possession
  signature over the connection's challenge; lookup carries nothing —
  the material is public.
- **Plain request/response, no push.** Unlike the relay connection, the
  directory has no server-initiated traffic, so a client writes a request
  and reads the reply on the same stream — no frame tagging, no reader
  task, no demultiplexing.
- **Possession is injected, exactly like connection auth.** The transport
  owns the register/lookup protocol but delegates the cryptography to a
  `Possession` verifier (a fresh challenge, and checking a signature
  against the submitted identity key), the sibling of `Authenticator`.
  The transport applies trust on first use through the crypto-free
  `Directory::register`. So the two halves of the trust model
  (decision record 0019) sit exactly where they should: possession in the
  injected verifier, binding in the directory.

`crates/tacenta-core/tests/networked_directory.rs` drives a real client
against a real server: a first registration, a same-key refresh, both
attacks turned away on the wire (hijack → `Rejected`, impersonation →
`PossessionFailed`), and a peer's lookup returning a bundle that opens a
working encrypted session.

## Considered

- **One protocol for relay and directory.** Fold register/lookup into the
  relay's `Request` / `Response`. Rejected for the same reason the crates
  are separate (decision record 0018): the relay's identity is being
  blind to message content, and a key directory is a different service
  with a different shape. One socket protocol per service keeps each
  codec and each server's job single.
- **Reuse the relay `Connection` (tagged frames, reader task).** That
  machinery exists to interleave responses with server push. The
  directory never pushes, so carrying the tag byte and the demultiplexing
  task would be complexity for a capability it does not use. The two
  transports share only the framing helpers (`read_frame` / `write_frame`).
- **Authenticate the whole connection before any request** (as the relay
  does). The relay must know *which device* it is serving to enforce
  per-queue authorization. The directory does not: lookup is public, and
  registration authenticates the *submitted identity*, not the connection.
  So the directory verifies per-`Register`, not per-connection.

## Why

The directory was a data model with an in-process demo; a real messenger
needs it reachable over the network, and putting the service in front of
it is what makes the trust model (decision record 0019) load-bearing
rather than a test fixture. Building it as the transport's sibling —
crypto-free protocol in the directory crate, socket plumbing in the
transport, crypto injected — keeps every layer in the crate that should
own it and reuses the framing already proven out by the relay transport.

## Co-location

`dir_server` takes an `Arc<Mutex<Directory>>` rather than owning the
store, so one process can run both services over a single directory: the
directory service writes registrations, and a relay server's
authenticator reads the same store to verify connections. The demo does
exactly this — a directory service and a relay server on two ports over
one shared directory — so it is now fully networked, with registration
and lookup over the socket and no in-process directory shortcut. The two
locks (relay state, directory) are independent and each is held only for a
synchronous dispatch, never across an `await`, so co-location adds no
deadlock surface.

## What would reopen this

- **Packaged as a server binary.** The co-located wiring is now
  `tacenta-server` (decision record 0021), a runnable `bind`/`serve`
  entrypoint a client points at; the demo uses it rather than re-wiring.
  Persistence and transport security remain open there.
- **No persistence.** The relay has snapshot/restore (decision record
  0016); the directory service has none yet, so registrations do not
  survive a restart. A directory snapshot, or a shared durable store, is
  future work.
- **Lookup is unauthenticated and unmetered.** Public material makes that
  correct, but a real deployment may want rate limiting or privacy for
  who-looks-up-whom; neither is addressed here.
