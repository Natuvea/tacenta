# 0103 — bounded group outbox capacity

## Decision

The bounded profile holds at most eight live logical sends per group. A logical
send is live until every recipient reaches a terminal disposition:
`relay_accepted`, `cancelled`, `cancelled_after_handoff`, or
`exhausted_unknown`. The durable group outbox refuses a ninth distinct live
logical ID with an explicit backpressure error. Exact replay of an existing
record returns that record; reusing its ID with changed immutable data
conflicts.

Terminal records remain attributable in durable storage and do not consume a
live slot. A newer accepted roster can cancel obsolete records but cannot erase
their ciphertext or handoff evidence simply to recover capacity.

## Considered

- Cap all historical send records permanently.
- Drop the oldest pending message when the cap is reached.
- Bound only live records and preserve terminal evidence.

## Why

The initial profile promises an explicit eight-message bound. Treating it as a
caller convention would allow unbounded plaintext and ciphertext retention
during offline fan-out or repeated membership changes.

## What would reopen this

A measured production profile may choose different per-group and global
backpressure budgets, with a versioned storage and scheduling policy.

## Amendment (0129)

"Terminal records remain attributable in durable storage" is bounded: the
records of the 16 most recent terminal logical sends are retained, and the
records of older terminal sends are dropped in the commit that first exceeds
that bound. The live bound of eight is unchanged, and terminal records never
consume a live slot. The control outbox follows the same rule with its own
bounds (8 live, 16 retained terminal).
