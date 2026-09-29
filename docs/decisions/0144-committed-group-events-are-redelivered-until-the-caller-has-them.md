# 0144 — committed group events are redelivered, with their event ID, until the caller has them

> Amends 0131 and 0133.

`GroupClient::receive` commits an item's disposition and the provider state,
acknowledges the committed prefix to the relay, and only then hands the events
to the caller (0131). Once the acknowledgement is sent, or once the provider
state that consumed the item's key is durable, the relay's copy is useless: a
redelivered ciphertext cannot decrypt. An event that was committed and not
handed over was therefore gone. GC-06's criterion "event redelivery retains a
stable ID" was not met, and 0131 and `docs/claims.md` said so.

## Decision

1. **An accepted event stays deliverable until the caller has acknowledged it.**
   The snapshot's `delivery_cursor` (written by nobody until now) is the number
   of group events the caller has been handed and needs no more: events with
   an ID below it are delivered. An accepted event with an ID at or above it is
   committed and undelivered, and its context is still in the `inbox` record of
   its disposition (0133), which is where redelivery reads it. Event IDs are the
   receiver's own stable counter (0139), so a redelivered event has the ID it
   had the first time.

2. **`receive` returns the undelivered events first.** `Inbound.redelivered`
   holds them in ID order, before any new mail is fetched, and
   `Inbound::events()` lists them ahead of the events of this call's items. This
   covers a failed acknowledgement after every item committed (the call returns
   the error and its events were never seen), a `receive` future that was
   dropped after its commits, a process that stopped between the commit and the
   caller's use of the event, and an `Unknown` write that landed (the item is
   committed, the coordinator froze before it could be returned). `receive_next`
   treats a redelivered event as mail.

3. **What counts as delivered.** The events a `receive` call returned with `Ok`
   are acknowledged when the caller calls `receive` again, or at once with the
   new `GroupClient::acknowledge_delivery`. A call that returned an error, was
   cancelled or was cut off by the process ending has handed nothing over. The
   coordinator tracks the highest event it handed over in this process and
   never advances the cursor beyond it, so a cancelled call cannot lose
   an event by acknowledging it. Acknowledging is one snapshot commit (the cursor
   change and the scrub below); a commit that does not succeed freezes like any
   other (0134) and the events stay undelivered.

4. **Delivered plaintext leaves the snapshot.** The same commit that advances the
   cursor rewrites the `inbox` records of the events it delivers without their
   context bytes, keeping the commitment and the disposition (the layout of a
   duplicate or refused record). Before this record the accepted plaintext stayed
   in the unsealed snapshot until 64 later records pushed it out (0133). It now
   stays until the caller acknowledges it, and the retention that redelivery
   needs is no longer than that.

5. **A gap is reported, not silent.** `Inbound.lost_events` is the number of
   events the receiver has issued at or above the cursor that are no longer
   retained (`GroupReceiver::events_issued` minus the ones the `inbox` still
   holds). Retention is the 64 newest `inbox` records, and one `receive` call now
   processes at most 32 relay items, so the events of one failed call always fit;
   they can be evicted only by further failing calls that keep committing mail
   without ever handing it over.

6. **Not changed.** A direct message is committed and then handed over exactly
   once (0132): its plaintext is not kept, and a crash between the commit and the
   caller's use of it still loses it. The relay side is unchanged: the prefix is
   acknowledged after its commits.

## Considered

- **Acknowledge on the next call only, never explicitly.** That is the default
  behaviour here, with the explicit call added for a caller that wants the
  cursor committed before it stops (a clean shutdown would otherwise redeliver
  the last batch once).
- **Explicit acknowledgement only.** Every existing loop would receive the same
  events on every call until it added the call.
- **Commit the cursor before returning the events.** That is at-most-once again:
  a crash after the commit loses them.
- **A separate durable record of undelivered events.** A second copy of the
  plaintext in a new layout, when the `inbox` record already holds the exact
  context bytes.
- **A callback from the application** (0131's reopening condition). It moves the
  acknowledgement to the application's time, which is what the explicit call does
  without an inversion of control.

## Limits this record leaves, exactly

- **At-least-once, not exactly-once.** A process that stops after `receive`
  returned and before the cursor was committed sees those events again after it
  restarts, with the same IDs. The application deduplicates by event ID, or calls
  `acknowledge_delivery` once it has stored them.
- The cursor and the scrub commit at the next `receive` or at
  `acknowledge_delivery`. Until then the delivered plaintext is still in the
  snapshot, which is unsealed (`docs/claims.md`).
- Events lost to eviction are counted in `lost_events` and cannot be recovered.
- Direct messages keep their at-most-once window (point 6).
- An event the `inbox` holds without its context (a scrubbed one, or a record
  written before this record) cannot be redelivered.

## The five questions

1. **Does this keep the trusted core small?** Yes. One accessor is added to the
   group crate (`GroupReceiver::events_issued`); the core is untouched.
2. **Is the behaviour owned by a written specification?** By this record.
3. **Can the security claim be reproduced?** `group_client::tests::redelivery`
   cuts the connection at the acknowledgement (the relay does and does not get it),
   runs the three-item crash matrix (`failed`, `unknown` that did not land and
   `unknown` that landed, at each item, recovered in process and by restart),
   checks the cursor, the scrub and `lost_events`, and runs the randomised
   receiver schedule against the invariant that no group event is lost.
4. **Does it preserve wire compatibility with a named profile?** Yes. No wire
   byte changes; the snapshot layout is unchanged, and a record scrubbed of its
   context is the layout a duplicate already had.
5. **Is this protocol functionality, or product coupling trying to enter the
   core?** Product coordination.

## Why

The durable state must not be able to say "this event exists" and "nobody will
ever show it". The context bytes were already durable, and the cursor field was
already in the format; what was missing was a rule for when an event is
finished with.

## What would reopen this

A store that seals or encrypts the snapshot (the scrub could then be dropped for
a shorter-lived key), a caller that needs exactly-once across a crash (a callback
or a transactional hand-off), or direct messages whose loss window matters enough
to keep their plaintext.
