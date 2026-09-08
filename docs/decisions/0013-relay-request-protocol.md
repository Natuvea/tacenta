# 0013 — the relay speaks a byte request/response protocol

## Decision

The relay exposes three operations — `Send`, `Poll`, `Ack` — as a typed
`Request`/`Response` pair with a byte-level codec (`encode_request` /
`decode_request` / `encode_response` / `decode_response`) and a single
byte-level entry point, `Relay::handle_bytes(&[u8]) -> Option<Vec<u8>>`.
A transport reads a frame, calls `handle_bytes`, writes the reply; it
needs no knowledge of the protocol. The relay is thereby
transport-ready without a transport yet existing.

The request codec **reuses the proven wire codec** for its payloads: an
envelope inside a `Send` is `tacenta_wire::encode`; the envelope list
inside a `Delivered` is `tacenta_wire::encode_stream` (the proven stream
framing). Only the thin integer/string headers around them are new, and
those are tested.

## Considered

- **A serde-derived format (bincode/postcard).** Fewer lines, but it
  pulls a serialization framework and its derives into the server's
  wire surface, and the encoding becomes whatever the library does
  rather than something specified here. The hand-rolled codec is small
  (the payloads are already the proven formats) and keeps the wire
  fully under our control — the same reasoning that put the envelope
  format in the spec rather than behind serde.
- **Coupling the protocol to a specific transport (WebSocket/TCP)
  now.** Rejected: the operations and their framing are transport-
  independent. `handle_bytes` is the seam; a socket is a later, thin
  adapter that moves bytes and does nothing else.

## Why

Separating *what the client can ask* (this protocol) from *how bytes
travel* (a future transport) keeps the networked step small and
testable: the whole request/response surface is exercised in-process
over `handle_bytes`, including the malformed-input rejection, with no
sockets and no async. When a WebSocket layer arrives it carries these
exact bytes and needs no protocol logic of its own. And because the
payloads ride the proven codec, a `Send`'s envelope and a `Delivered`'s
envelope list are framed by verified code; only the small headers are
tested.

## What would reopen this

- Server-push (the relay notifying a client of new mail without a poll)
  needs a duplex model the current request/response shape does not
  cover; it would extend, not replace, this protocol.
- Authentication and session binding (which client may act as which
  device) belong around this protocol, at the transport/auth layer, and
  will add a handshake before these operations are accepted.
- If the header encoding ever needs to be cross-checked against other
  implementations, it graduates from tested to spec-with-vectors like
  the envelope format.
