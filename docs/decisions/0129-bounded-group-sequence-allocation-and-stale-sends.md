# 0129 — bounded group sequence allocation and stale sends

> Amends 0095. Amended by 0135.

## Decision

The group outbox allocates logical sequences. `GroupOutbox::next_sequence`
returns, for a `(revision, sender)` pair, zero when the outbox retains no send
for it and otherwise one more than the highest sequence it retains, and reports
`SequenceExhausted` when that highest sequence is `u64::MAX`. `record` refuses
a new logical ID whose sequence is not greater than every retained sequence
for its `(revision, sender)` with `SequenceOrder`. An exact replay of a
retained record still returns `Duplicate` and a changed record under a retained
ID still conflicts. Sequences are per revision, so a new revision starts again
at zero, as 0095 says.

The outbox also refuses a send for a revision older than the newest roster it
has applied. `cancel_for_newer_roster(revision)` raises that applied revision
and never lowers it; `record` refuses a new send whose revision is below it
with `StaleRevision`. A send at the applied revision is allowed. Replaying a
transcript does not apply a revision until the caller does, so recovery
accepts every record that was accepted when it was first written.

The retained maximum is the high-water mark, which is sound because terminal
records are retained (decision 0103). Any future rule that prunes terminal
sends must first carry an explicit per-`(revision, sender)` high-water mark in
the durable state; without one it would let a sequence be reused.

## Considered

- Say the caller owns allocation and leave the crate to check nothing. Reuse
  is then caught only when the same ID arrives with a different payload, and a
  caller that restarts its counter at zero after a crash would reuse a
  sequence whose send was already handed off.
- Persist a separate counter. That needs a new durable record and a migration,
  for a bound the retained sends already give.
- Refuse only stale sends and leave sequences unenforced.

## Why

0095 states that a sequence is monotonic, allocated with the record and never
reused, and nothing enforced it. The outbox is the one value that sees every
retained send, so it can allocate and check without new storage. A reused
sequence is an availability fault, not a confidentiality one: the receiver
refuses the changed content as a conflict and the message is lost. Refusing a
send for a superseded revision at the outbox closes the gap the removal-race
recovery left, where only recovery cancelled such a send and the live outbox
accepted it.

## What would reopen this

Pruning of terminal sends, a multi-device profile with per-device sequences, or
a replay window that admits out-of-order allocation.

## Amendment (0135)

`GroupClient::send_group` allocates with `next_sequence`; it no longer keeps its
own copy of the rule, and its sequences start again at zero at each revision.
The client's compaction keeps every live send and the sixteen most recent
terminal ones, so the newest send of the current revision is always retained and
the retained maximum remains the high-water mark this record requires; a send at
an older revision is refused as stale.
