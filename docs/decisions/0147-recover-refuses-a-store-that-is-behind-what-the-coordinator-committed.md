# 0147 — `recover` refuses a store that is behind what the coordinator committed

> Amends 0143.

0143 fences a second writer: `DurableStore` remembers the generation it last
recovered or published and commits with `commit_after` against it, so a store
that has moved (another writer published, a backup was put back) refuses the
next commit, the handle latches, and the coordinator is frozen until `recover`
has read the store and reset the client's pairwise state to it. The
documentation named `recover` as the remedy for every one of those cases,
including a restored backup. A verification of the second fix round showed that
for a backup it is not.

## The failure

A coordinator on the native file store sends three direct messages (generation
4) while a backup taken after the first (generation 2) exists. The backup is put
back over the running store. The next send is refused as `Frozen`, as 0143
designed. `recover()` then succeeds: `DurableStore::recover` sets the generation
it observes to the one the store now holds and keeps only the highest generation
it ever attempted, so the rollback is visible inside the process and nothing
looks at it. The client's pairwise state is reset to the backup's, and the next
message is encrypted at a ratchet position the peer already used. The peer
received one, two and three, and dropped the message sent after `recover()`
(reproduced: `dropped 1`). 0143 and `docs/claims.md` presented a restored backup
as handled ("freezes instead"); it froze, and the remedy then accepted the
rollback without a word.

## Decision

1. **The handle remembers the highest generation it saw durably committed.**
   `DurableStore` keeps the highest generation of a write that reported
   `committed`, and of any snapshot it recovered. A write that failed or whose
   outcome was unknown does not raise it: an unknown write may or may not have
   landed, and recovering either the generation before it or the one it wrote is
   a legitimate result of a crash (0134).

2. **`recover` refuses a store behind that mark.** `GroupClient::recover` reads
   through the handle, and when the store holds a snapshot older than the mark
   (or no snapshot at all) it fails with the new `GroupError::Rollback`. It
   changes nothing: the client's provider state, the coordinator's snapshot and
   group state and the store are as they were, the store handle stays latched,
   and the coordinator stays frozen. Calling `recover` again gives the same
   answer for as long as the store is behind. A snapshot with a higher
   generation, another writer's, is what `recover` adopts, as in 0143.

3. **The way on is the caller's decision, and it is not a method.** To continue
   from the older state the caller drops the coordinator, connects a client from
   `recovered_provider_state(store)` and calls `GroupClient::open`: a new handle
   has no memory of the newer snapshot, and `open` accepts what the store holds
   when the client's state equals it (0143). That is the caller vouching for the
   state, and the peers, which have seen the positions since the backup, drop
   what is sent at them (a test pins this). Or the caller starts a new session
   over a new identity, which has no history to reuse. `GroupClient` has no
   `recover_accepting_rollback`: a call that adopts the older state in place is
   one line from the retry loop that calls `recover` after every freeze, which is
   the path that failed.

## Considered

- **Compare the client's exported state with the snapshot's in `recover`.** The
  client is legitimately ahead of the durable snapshot after a failed or unknown
  write (an operation consumed pairwise state it never recorded), and `recover`
  exists to reset it. The generations are the only comparison that separates the
  two.
- **Persist the mark outside the store.** A second file has no better standing:
  it is unsealed too, and a backup tool that restores one restores the other.
- **A method that adopts the older state on request.** Rejected above.
- **Reuse `StateMismatch`.** That error is for `open`, a client against a
  snapshot; here the client is the coordinator's own and the store went back.

## Limits this record leaves, exactly

- The mark lives in the handle. A process that restarts, or a caller that
  builds a new coordinator over the store, has no memory of what the previous
  one committed; `open` accepts the snapshot the store holds if the client
  matches it. There is still **no rollback detection across handles**: the
  store is unsealed and anyone who can write it can write any generation and
  state (0143).
- The comparison is by generation number. A different snapshot with the same or
  a higher number than the mark is not detected. An idle second writer that
  observed a reused number is not covered; that case was not tested.
- A rollback that happens while the coordinator is frozen for another reason is
  refused the same way; the caller then follows point 3.
- Peers drop, without telling the sender, what a reopened older state sends at a
  position they have seen.

## The five questions

1. **Does this keep the trusted core small?** Yes. Product coordination only.
2. **Is the behaviour owned by a written specification?** By this record and the
   ones it amends. The snapshot layout does not change.
3. **Can the security claim be reproduced?** `group_client::tests::store_rollback`
   puts a backup back under a running coordinator over an in-memory store and
   over the native file store: the next send is `Frozen`, `recover` is `Rollback`
   twice, the store is not written, the peer is shown exactly what was sent
   before, and a reopened coordinator over the backup runs and is dropped by the
   peer. A write that failed or was unknown does not raise the mark, and another
   writer's newer snapshot is adopted. `operation_store` unit tests pin the
   handle.
4. **Does it preserve wire compatibility with a named profile?** Yes. Nothing on
   the wire or in the snapshot changes.
5. **Is this protocol functionality, or product coupling trying to enter the
   core?** Product coordination.

## Why

A recovery that resets the client to whatever the store holds is right when the
store is where the coordinator left it or ahead of it, and wrong when it is
behind, because the peers have seen what the older state has not yet done. The
handle is the one place that knows what was committed, so it is where the
question is asked.

## What would reopen this

A sealed store with a monotonic counter the platform keeps, a supported
multi-process profile with a lease (0143), or a caller that needs to resume from
a backup in place and can vouch for the peers.
