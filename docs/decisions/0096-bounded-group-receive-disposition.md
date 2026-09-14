# 0096 — bounded group receive disposition

## Decision

After successful pairwise processing, the bounded group receiver creates one
durable disposition before it acknowledges the corresponding relay prefix or
exposes an application event. The disposition is one of accepted, terminal
rejection, or deferred. It carries the provider state effect, group context,
dedup key, content commitment, and a stable event ID when accepted.

The dedup key is `(group_id, revision, sender_identity, sender_device,
sequence)`. A 64-sequence sliding window stores the accepted content
commitment for each active sender/device. An exact duplicate creates no second
inbox item and reuses its stable event ID. The same key with a changed
commitment is a conflict. A sequence older than the retained window and an
old-revision application message are terminally refused.

Only a known group whose sender and local recipient are active in the current
roster may defer a message from either of the next two revisions. Deduplication
runs before the four-item future queue capacity check. An exact duplicate
reuses its slot; a changed commitment conflicts; a full queue terminally
rejects the newest candidate. Pending and removed local identities have no
application-message future queue.

A pairwise-authenticated but invalid, unauthorised, stale, or over-capacity
group payload retains its provider state effect and gets the required durable
terminal/deferred disposition. It creates no application effect. The
cumulative acknowledgement may not cross any item lacking one of these durable
dispositions.

## Considered

- Acknowledge every pairwise-decryptable payload immediately.
- Treat a duplicate as a second application event.
- Defer arbitrary future revisions.
- Commit a bounded disposition before acknowledgement.

## Why

Cumulative acknowledgement makes one unsafe item block later work, so the
receiver needs a durable decision for every processed item. The narrow
future rule permits known, near-term reordering without making pending or
removed identities application members. Stable event IDs let applications retry
consumption without claiming exactly-once callbacks across crashes.

## What would reopen this

A new revision window, multi-device profile, durable-store implementation, or
application transaction model needs a versioned successor. This record defines
no current client receive integration; GC-06 supplies it with the provider and
operation store.
