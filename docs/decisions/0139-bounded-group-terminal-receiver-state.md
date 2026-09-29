# 0139 — bounded group receiver state after removal or closure

> Amends 0114. Amended by 0142.

## Decision

A receiver state whose local binding is not an active member of its accepted
roster, because the local member was removed, was never admitted, or the roster
is closed, is a valid terminal state. `GroupReceiver::decode_state` restores
it, and the restored receiver refuses every application context with
`NotActive`, as the live receiver already did. `GroupReceiver::status` reports
`Active`, `NotMember` (removed or never admitted) or `Closed` so that a caller
can tell a recovered terminal state from a live one; a closed roster reports
`Closed` whether or not the local member is listed.

A terminal state carries no accepted entries and no deferred contexts. Both
are cleared or drained when the successor that ended membership is installed,
and no application context is accepted or deferred afterwards. Decoding
refuses a terminal state that carries either with `NonCanonical`. The state's
bytes and version are unchanged, so no migration is needed. A later successor
that admits the member again installs normally.

This replaces the rule in 0114 that decode rejects an inactive local binding.
Sender bindings in accepted entries and in deferred contexts must still be
active members of the roster.

## Considered

- Keep refusing (`NotMember`). The coordinator writes this state when the
  successor removes the local member or closes the group, and then cannot read
  it back, so a removed member cannot restart around its own removal and the
  authority's leave makes every member's state unrecoverable.
- Delete the state on removal. That loses the stable event IDs of accepted
  events the application may not have consumed yet.
- A separate tombstone format with its own version. That adds a migration for
  information the roster and the local binding already carry.

## Why

Recovery has to be able to read what the writer wrote. The live receiver is
already terminal in these cases and refuses everything, so restoring it adds no
new behaviour to refuse. The empty-entries rule keeps the state small and
keeps a forged value from smuggling retained plaintext or deferred work past a
removal. `status` makes the terminal condition an explicit value rather than
an error the caller must interpret.

## What would reopen this

A rejoin or history feature that needs to retain events across a removal, or a
different representation of closure.
