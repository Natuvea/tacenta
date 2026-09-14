# 0112 — bounded group outbox transcript recovery

## Decision

A group outbox recovers by replaying its ordered `TCGI`, `TCGP`, `TCGH`, and
`TCGA` records. Each progress record decodes its canonical application context,
checks that it reproduces the recovered immutable logical send, and verifies
its 32-byte payload commitment through the caller-supplied core helper before
it changes recipient progress.

`TCGH` may advance the next exact attempt only and its stored disposition must
match the resulting bounded retry state. `TCGA` requires a preceding handed-off
recipient. Unrecognised non-group transcript entries are ignored so one
combined operation snapshot can retain other work; malformed or unknown `TCG*`
records freeze group recovery.

## Considered

- Rebuild only the latest visible recipient status.
- Trust progress records without replaying their immutable context.
- Replay every bounded group record against the recovered intent.

## Why

The transcript is useful after restart only if it recreates the same bytes and
retry boundary. Replaying an exact context with the core commitment binds the
pairwise ciphertext to the original group, revision, sender, recipient, and
payload without adding a crypto dependency to the group-policy crate.

## What would reopen this

A journal compaction scheme may replace historical records with an authenticated
checkpoint, provided restore validates the same logical state and does not turn
an uncertain handoff into relay acceptance.
