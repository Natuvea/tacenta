# 0122 — bounded group-control transcript

## Decision

The operation snapshot retains at most 64 group-control records. A successful
control transition appends its complete set of durable records and then drops
the oldest retained records as part of the same candidate snapshot. Recovery
uses only the latest self-contained roster-view or invitation-book checkpoint,
so eviction never requires replaying an unbounded history.

## Considered

- Keep every control record indefinitely.
- Reject all control work after the retention limit.
- Retain bounded checkpoints and evict older transcript records atomically.

## Why

The experimental control plane can change membership many times. An unbounded
operation snapshot turns ordinary control traffic into a local storage denial
of service. Checkpoints preserve the current recoverable state while giving
the snapshot a fixed record-count bound.

## What would reopen this

A signed replicated control log can use its own compaction proof, but must
provide an equally explicit storage and recovery bound.

## Amendment (0133)

The 64-record bound is unchanged. A new checkpoint (`TCGV`, `TCGB`, `TCGO`,
`TCGX`) now replaces the previous checkpoint of its kind in the same candidate
snapshot, so at most one of each is retained and the byte size of the transcript
is bounded, not only its record count.
