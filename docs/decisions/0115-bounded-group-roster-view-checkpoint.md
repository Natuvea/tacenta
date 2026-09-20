# 0115 — bounded group roster-view checkpoint

## Decision

The accepted bounded roster view has a canonical checkpoint containing its
current roster preimage and core roster commitment. Restore requires the
locally pinned authority binding and recomputes the commitment before it
reconstructs the view. A genesis checkpoint also satisfies genesis rules;
later checkpoints rely on the selected durable operation generation having
already recorded the predecessor-checked transition that produced it.

The checkpoint is a recovery value, not a substitute for authority-channel
authentication or successor validation. A client still authenticates every new
control transition before changing the restored view.

## Considered

- Reaccept the newest roster without checking its commitment.
- Rebuild current membership from invitation state.
- Restore a core-verified roster checkpoint with a pinned authority.

## Why

Group receiver and outbox recovery need the same accepted membership epoch
after restart. Persisting just invitations or a roster digest cannot reproduce
the full active-member rule used by those components.

## What would reopen this

Detached authority signatures, multiple authorities, or an authenticated
checkpoint chain require a successor control-state format.
