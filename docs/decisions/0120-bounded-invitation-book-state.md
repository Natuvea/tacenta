# 0120 — bounded invitation-book state

## Decision

The bounded group profile persists an invitation book as one canonical,
group-scoped checkpoint. The checkpoint names the group, contains at most 32
records in strictly ascending invitation-ID order, and retains every immutable
invitation field with its lifecycle disposition. Decoding rejects duplicate or
out-of-order IDs, another group, non-canonical field lengths, unsupported
policy, invalid members, reserved revisions, and trailing bytes.

The checkpoint is an aid to a future durable coordinator. It does not turn an
invitation into membership: only a separately authenticated roster successor
admits a recipient.

## Considered

- Recreate invitation state from unbounded relay history.
- Retain only pending invitations.
- Persist a bounded canonical checkpoint.

## Why

Authority retries and restart recovery need the prior lifecycle result. Keeping
revoked, expired, and admitted records prevents a reused identifier from being
mistaken for a new invitation, while the bound makes recovery storage and
parsing finite.

## What would reopen this

A production membership protocol may replace this coordinator checkpoint with
a signed replicated log, while retaining its explicit size limit and immutable
identifier rule.
