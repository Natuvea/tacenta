# 0017 — server push: notify, don't poll; relay stays blind

## Decision

When a message is routed to a device that has a connected client, the
server pushes that client a notification so it fetches immediately,
rather than the client polling on a timer. Three constraints keep the
existing boundaries intact:

- **The relay stays blind and synchronous.** It gains nothing — no
  channels, no async, no crypto. The *transport* holds the set of
  connected devices and their notification channels.
- **The push is a wakeup, not the payload.** A notification carries no
  data; the client responds by `Poll`, so all delivery and cursor logic
  stays in the one already-correct path. The server never duplicates
  delivery into the push.
- **One task owns each socket.** The per-connection task `select!`s
  between reading a request and receiving a push, so responses and
  pushes never race for the writer. No locking of the stream.

After the handshake, every server→client frame carries a one-byte tag
(`0` response, `1` push); the client's reader task demultiplexes them
into a response channel (paired with requests) and a notification
channel (`Connection::next_notification`).

## Considered

- **Push the new envelopes directly** in the notification. Tempting (one
  round trip instead of notify-then-poll), but it splits delivery across
  two code paths and complicates cursor accounting — the pushed
  envelopes versus what a `Poll` returns. A content-free wakeup keeps a
  single source of truth for what a device has and where its cursor sits.
- **Long-poll instead of duplex push.** A blocking `Poll` avoids the
  client-side demux, but ties a request up per waiting client and needs
  the async wait inside the request path — which would pull `await` (and
  thus the runtime) toward the sync, blind relay. Duplex push keeps the
  relay untouched.
- **The relay firing notifications itself.** It knows the recipient of an
  enqueue, but making it fire pushes means giving it channels and an
  async runtime, breaking decision 0012. Instead the transport learns the
  recipient by decoding just the `Send` it is already routing.

## Why

Polling is the wrong default for a messenger: either latency (poll
rarely) or waste (poll often). Push makes delivery immediate while
leaving every proven and blind property in place. The cost is that the
transport now decodes a request to see a `Send`'s recipient — a small,
deliberate step past pure byte-moving, justified because the alternative
(relay-side push) would breach a stronger invariant. The demo shows it:
each recipient prints "notified of new mail" before decrypting, and a
transport test (`recipient_is_pushed_on_send`) pins it.

## What would reopen this

- Offline delivery / mobile push (APNs, FCM) is a different channel for
  *disconnected* devices; this in-band push covers only connected ones.
  Both can coexist — the queue persists regardless (decision 0016).
- Fan-in load: a device receiving a burst gets one wakeup per send here.
  Coalescing (at most one outstanding notification) is an easy refinement
  when it matters.
- Backpressure on the push channel (currently unbounded) wants a bound
  once connection counts are real.
