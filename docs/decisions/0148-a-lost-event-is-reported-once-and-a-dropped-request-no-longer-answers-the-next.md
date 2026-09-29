# 0148 — a lost event is reported once, and a dropped request no longer answers the next one

> Amends 0144.

A verification of the second fix round found two faults in the corner of 0144
where a `receive` does not complete. One is in 0144's own rule for lost events;
the other is older than this branch and is in the transport, but 0144 relies on
it.

## The failures

1. **`lost_events` never clears, and `receive_next` stops waiting.** 0144 point 5
   defines `Inbound.lost_events` as the events issued at or above the delivery
   cursor that the `inbox` no longer retains, and promises that a gap is reported,
   not silent. The cursor moves only when the coordinator has handed events over.
   A lost event is never handed over, so the cursor never passes it and every
   later `receive` reports the same loss, in every process, until a new event
   arrives. `receive_next` counts a non-zero `lost_events` as mail, so it returns
   at once, forever: a hot loop. Reproduced with a consumer that crashes after
   each `receive` (so that no acknowledgement is ever written) while a registered
   peer sends 32 junk payloads per round: the event is evicted in the third
   round, and every later call reports `lost_events = 1`, the cursor stays 0 and
   `receive_next` returns immediately. One failed call cannot cause this;
   eviction needs 32 further mail items to be committed without the events ever
   being handed over.
2. **A `receive` future that is dropped leaves the connection out of step.** 0144
   says the events of a call that was cancelled "come back on the next call".
   They do, but the next call fails: `Connection::request` writes the frame and
   then waits on the channel that the reader task feeds with responses. If the
   future is dropped after the write, the response arrives later and stays in the
   channel, and the next request takes it for its own. `receive` then answers
   `expected a delivery` or `acknowledgement was not accepted`, sometimes several
   calls in a row (reproduced at the branch base too: the fault is not from this
   branch). If the future is dropped while the frame is being written, half a
   frame may be on the wire and the next frame follows it.

## Decision

1. **A loss is reported by the call that finds it, and acknowledged like an
   event.** A `receive` that reports `lost_events > 0` counts every event it saw
   the receiver issue before the call as handed over: the ones still retained are
   in `redelivered`, and the rest are the loss it reports. The next call commits
   the cursor to that count, as it does for events, and reports nothing more.
   `receive_next` returns for the call that reports the loss and then waits. The
   report has the guarantee an event has: at-least-once. A process that stops
   before the next call commits the cursor reports the loss again after a
   restart (a consumer that crashes after every `receive` sees it once per
   process); after the commit it does not come back. No field or record is added:
   the cursor already says which events are finished with.

2. **`Connection::request` is cancel-safe for the relay.** It counts the requests
   whose frames went out and whose responses it has not taken, and drains that
   many stale responses before it writes the next frame, so a dropped request
   cannot answer its successor. A future dropped while its frame was being written
   marks the connection unusable, and the next request fails at once with
   `BrokenPipe`; the client's existing reconnect path (`receive` reconnects on an
   I/O error) then takes over. Nothing else about the framing changes.

## Considered

- **Keep `lost_events` a level and have `receive_next` ignore it.** A caller that
  only uses `receive_next` would never learn of the loss. Rejected.
- **A separate durable field for the reported loss.** A new snapshot layout for
  a fact the cursor already carries. Rejected.
- **Make the loss durable before it is returned.** It would report at-most-once,
  the wrong way round for a notice the application must see.
- **Fix the transport in `Client` only** (discard the connection whenever a
  `receive` is cancelled). The client cannot see a cancellation: a dropped
  future runs no code. The connection is the only place that can know its own
  request was abandoned.
- **Fix the directory and account connections too.** `DirConnection` and
  `AccountConnection` have the same shape (write a frame, then read one, no
  correlation). They are not on the path of `receive`, and this record does not
  change them; see the limits.

## Limits this record leaves, exactly

- **The directory and account connections are not cancel-safe.** A dropped
  directory lookup (in `send_group` or `install_roster` while preparing a
  recipient) or account call can leave a response on the connection for the next
  call to read. Not changed, not tested.
- **A future dropped inside `receive` between a decrypt and its commit** is not
  covered. The randomised cancellation test drops `receive` at random points 120
  times and nothing was lost, but that is a test, not a proof: an item whose key
  the provider consumed and whose disposition was not committed cannot be
  decrypted again.
- The loss report is at-least-once (point 1). A consumer that must count losses
  exactly deduplicates by the cursor.
- A dropped future in the middle of a frame costs a reconnect, and a reconnect
  is what the client does on any I/O error.

## The five questions

1. **Does this keep the trusted core small?** Yes. The change is in product
   crates (`tacenta-client`, `tacenta-transport`).
2. **Is the behaviour owned by a written specification?** By this record. The
   framing of the relay protocol is unchanged.
3. **Can the security claim be reproduced?** `redelivery::a_lost_event_is_reported_once_and_then_cleared`
   (the crash loop under junk: the loss once, then zero, the cursor at 1,
   `receive_next` waiting, no report after the restart that follows the
   acknowledgement); `drain_faults_and_receiver_schedule::a_cancelled_receive_does_not_break_the_next_call`
   (120 receives dropped at random times, no failed call, every event shown);
   in `tacenta-transport`, one test drops a request after its frame was written
   and one drops a request half way through its frame.
4. **Does it preserve wire compatibility with a named profile?** Yes. No bytes
   change, on the wire or in the snapshot.
5. **Is this protocol functionality, or product coupling trying to enter the
   core?** Product coordination and transport plumbing.

## Why

A notice that repeats for ever is a notice nobody reads, and a loop that never
waits is a fault. A request whose future can be dropped must leave the
connection as it found it, because the caller that drops it is the one that
asks again.

## What would reopen this

A caller that must count losses exactly, a directory or account call that is
cancelled in practice, or a provider whose decrypt yields between the key being
consumed and the state being returned.
