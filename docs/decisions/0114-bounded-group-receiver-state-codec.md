# 0114 — bounded group receiver state codec

## Decision

The bounded receiver has a versioned local-state codec containing its accepted
roster and core-verified roster digest, local binding, next stable event ID,
current-revision dedup entries, and deferred contexts. Decode rejects values
outside the profile's 256 KiB state bound, invalid roster/context encodings,
changed core commitments, duplicate keys or event IDs, inactive sender/local
bindings, non-current accepted revisions, and out-of-range deferred revisions.

The codec persists no application delivery acknowledgement. It restores stable
event IDs and the four-item deferred queue so the client can repeat durable
application disposition before it acknowledges relay delivery.

## Considered

- Rebuild receiver state from raw relay traffic after restart.
- Serialize opaque in-memory Rust structures.
- Encode a bounded, validated receiver state with supplied core verifiers.

## Why

Receive durability needs its dedup and deferred state to survive process loss.
Canonical recovery retains the same refusal and event-ID behavior without
making the group policy crate depend on a crypto implementation.

## What would reopen this

A larger profile or an authenticated checkpoint format needs a versioned
successor with new measured storage bounds and migration rules.
