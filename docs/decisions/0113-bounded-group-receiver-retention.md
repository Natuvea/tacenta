# 0113 — bounded group receiver retention

## Decision

The receiver retains accepted dedup entries only for the current roster
revision. For each sender binding it retains at most the 64-sequence sliding
window defined by the bounded profile. Installing an accepted successor drops
old-revision accepted entries before revalidating deferred messages, since old
application contexts are terminally refused regardless of their former dedup
status.

An incoming sequence at or below the current sender window's expired boundary
is refused as `sequence_expired`; an exact retained key retains its original
event ID. Deferred entries keep their existing four-item bound.

## Considered

- Retain every accepted entry for the life of the group.
- Drop all dedup entries after every acknowledgement.
- Keep the specified current-revision, per-sender sliding window.

## Why

Durable recovery cannot be bounded if normal valid traffic grows its dedup
state without limit. The current roster is the only revision that can accept
application content, so retaining prior-revision entries provides no valid
duplicate behavior.

## What would reopen this

A later history or cross-revision receipt feature needs its own bounded,
versioned event-retention rule; it cannot silently expand the receive window.
