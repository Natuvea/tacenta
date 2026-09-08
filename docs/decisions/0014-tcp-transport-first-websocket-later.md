# 0014 — length-prefixed TCP transport first; WebSocket/TLS later

## Decision

`tacenta-transport` is a TCP server and client that move
length-prefixed frames (`[u32 big-endian length][frame bytes]`) between
a socket and `tacenta_relay::Relay::handle_bytes`. It is a thin adapter
with no protocol, delivery, or crypto logic of its own. It lives in its
own crate so the blind relay keeps its minimal dependency set (decision
0012) — the async runtime (tokio) is here, not in the relay.

Production will use **WebSocket over TLS**; this TCP cut is the first
networked step, chosen because the framing and the `handle_bytes` seam
are identical either way, so the upgrade is contained.

## Considered

- **WebSocket + TLS now** (tokio-tungstenite, rustls). The right
  production transport, but it front-loads a TLS story (certificates,
  trust configuration), a heavier dependency, and a handshake — none of which changes what this layer
  *does*: hand complete request frames to `handle_bytes`. Deferring it
  keeps the first networked milestone small and lets the socket layer
  be validated in isolation.
- **No length prefix, rely on the request codec's self-delimitation.**
  The request codec is self-delimiting given a complete buffer, but TCP
  is a byte stream with no message boundaries, so the reader still needs
  to know where one request ends. An explicit length prefix is the
  standard, simplest answer; the alternative (parse-as-you-go against
  the request grammar) couples the transport to the protocol, which the
  `handle_bytes` seam exists to avoid.

## Why

Keeping the transport a byte-moving adapter — no awareness of what a
frame *means* — is what let the entire request/response surface be
tested in-process first (over `handle_bytes`, decision 0013) and then
validated over a real socket with almost no new logic. The capstone
integration (`tests/networked_conversation.rs`) runs a real end-to-end
encrypted conversation between two clients through a running server on a
TCP port: crypto + transport + blind relay + the proven wire and
delivery layers, as one networked system. Swapping TCP for WebSocket/TLS
later touches only this crate.

## What would reopen this

- Server-push (delivering new mail without a poll) needs a duplex frame
  loop rather than strict request→response; WebSocket's message model
  suits it and would likely arrive together with the WebSocket upgrade.
- Backpressure, connection limits, and idle timeouts are unaddressed in
  this first cut and are the obvious hardening once the transport is
  more than a functional demonstration.
- Authentication (binding a connection to a device identity) sits
  between the socket and `handle_bytes`; it is a handshake this adapter
  will gain, and is deliberately absent now.
