# 0109 — bounded group relay acceptance

## Decision

After a relay accepts an exact group handoff, the client records a `TCGA`
outbox entry for that committed logical ID and recipient. The entry records the
canonical application context, core payload commitment, exact ciphertext, and
the `relay_accepted` recipient disposition. It commits the candidate outbox
before reporting relay acceptance to the sender.

Relay acceptance ends automatic retry for that recipient but does not create a
recipient application-delivery or read-receipt claim. Failed or unknown
publication freezes the operation and leaves the live recipient in its prior
handoff state so recovery can reconcile it without inventing a result.

## Considered

- Treat relay response as an application delivery receipt.
- Update only an in-memory recipient disposition after relay response.
- Commit a distinct relay-acceptance record before exposing the result.

## Why

The sender needs durable, truthful per-recipient status after a partial fanout.
Relay acknowledgement is observable, while application consumption is not.

## What would reopen this

A production receipt protocol can add authenticated application status as a
separate operation; it cannot reinterpret this relay observation.
