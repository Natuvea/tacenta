# 0143 — the coordinator opens only its own state, fences a second writer, and keeps the freeze until recovery succeeds

> Amends 0091, 0132 and 0134.

`GroupClient` (0131) makes the operation snapshot the only durable copy of the
client's pairwise state (0132) and latches after a write that did not commit
(0134). Three gaps let a coordinator reuse a ratchet position or run on state
that no snapshot recorded. Each was reproduced against the integrated branch.

## Decision

1. **`open` refuses a client whose pairwise state is not the snapshot's.**
   When the store holds a snapshot, `GroupClient::open` exports the client's
   state and requires it to equal the snapshot's `provider_state` byte for
   byte. A client of another identity, or a snapshot with no provider state, is
   `GroupError::Recovery` (the snapshot does not fit this client). A client of
   the same identity in a different state is the new
   `GroupError::StateMismatch`, whether the client is behind the snapshot (a
   backup, an application's own older state blob) or ahead of it (messages sent
   or received through the plain client before it was wrapped). The remedy is
   the one the documentation already gave: connect the client from
   `recovered_provider_state`. Nothing is adopted, restored or overwritten, so
   a refused `open` leaves the store and the client untouched. A store that
   holds nothing still gets its first snapshot from the client's state.

   For the comparison to be usable the exported state must be a function of
   the state. It was not: `Client::export_state` walked a `HashSet` of peer
   sessions, so two exports of one client could differ in the order of the
   sessions (12 exports after a restore, 9 differed). The peers are now
   exported in the order of their address, and a client restored from an
   export exports the same bytes again (12 of 12 in the test). An old export
   that a previous build wrote in another order restores as before; only the
   equality test in `open` depends on the order, and no snapshot written by
   `GroupClient` exists outside this branch.

2. **A commit is refused when the store is not where the coordinator left it.**
   `OperationStore` gains `durable_generation` (the generation of the newest
   durable snapshot, `None` for an empty store) and `commit_after(expected,
   snapshot)`, which publishes only if the newest durable snapshot still has
   generation `expected`, and otherwise writes nothing and reports `failed`.
   The provided implementation reads and then writes. `DurableStore`, the
   handle every `GroupClient` commit goes through, remembers the generation it
   last recovered or published and commits with `commit_after`; a refusal
   latches like any other failed write, so the coordinator is frozen and its
   `recover` reads the other writer's snapshot and resets the client's
   pairwise state to it. Nothing was sent for the refused commit: every
   pairwise operation commits before its ciphertext leaves the process
   (0132).

   `FileOperationStore` overrides both with a lock: it takes an exclusive
   advisory lock on `<path>.lock` (`File::lock`), reads the 13-byte header of
   the snapshot file, compares and writes atomically before it releases the
   lock, so two coordinators on one local file cannot both publish from the
   same generation.

3. **`recover` keeps the freeze until it has succeeded.** `recover` sets the
   coordinator's own freeze first and clears it only after the snapshot was
   read, the client's pairwise state restored and the group state rebuilt. A
   `recover` that fails at any step leaves the coordinator frozen, including
   the case where the store latch was lifted by the read (0134 says the
   coordinator "must recover the selected durable generation before it can
   retry"). The group state is replaced only by a rebuild that succeeded.

## The failure this prevents

- A client restored from an older state, or advanced by a plain send, was handed
  a store holding the newer snapshot: `open` succeeded and the next
  `send_direct` encrypted at a ratchet position the peer had already seen. The
  peer received 0 of 1 (reproduced). The other direction is the same failure.
- An application and an extension each held a coordinator over one store; each
  sent one direct message from the same generation; one publication overwrote
  the other under the same generation number and the peer received 1 of 2.
- A `recover` that failed after the store latch had been lifted left a
  coordinator that was no longer frozen, running on the in-memory state the
  failed operation had advanced and never recorded.

## Limits this record leaves, exactly

- **One writer per store remains a precondition.** The fence turns a second
  writer's commit into a freeze; it does not make two writers a supported
  configuration. Two live coordinators can still both encrypt at one position
  before either commits, and the one that loses the commit never sends it.
- The provided `commit_after` is check-then-write: two processes that check at
  the same instant can both pass. Only a store that overrides it with an atomic
  check (the file store, on one machine) closes the race. The file lock is
  advisory (it binds cooperating processes only), is meaningless on a network
  filesystem that does not honour it, and does not exist on `wasm32`, where the
  file store is not built.
- The equality test compares whole exported states. A client that legitimately
  changed its state outside the coordinator (for example by publishing new
  prekeys) is refused until it is connected from the snapshot; that costs a
  reconnect, not data.
- The fence does not authenticate the store. A party that can write the store
  can write any generation and any state (the snapshot is unsealed and has no
  rollback detection, 0078 is not attached).
- `recover` on a store that holds no snapshot is a `Recovery` error and leaves
  the coordinator frozen.

## Considered

- **Restore the snapshot's state into the client in `open`** (the direction the
  review suggested first). Rejected for the ahead case: the peer has already
  seen the positions the client consumed, so restoring the older snapshot
  state reuses them, which is the failure. Refusing is the only safe answer
  when the two are not equal, because the coordinator cannot tell which is
  older.
- **Adopt the client's state when it is ahead** by publishing it. Rejected: the
  coordinator cannot verify that the client's state descends from the
  snapshot's, and a snapshot written from a different history would replace
  the durable root.
- **Compare a digest** instead of the bytes. Equivalent to the bytes once the
  export is a function of the state; the bytes need no extra primitive and the
  comparison is local.
- **A generation argument on `commit` itself.** It changes every implementation
  of the port and every test store. `commit_after` has a provided
  implementation, so existing stores keep working and gain the fence at the
  handle.
- **A lock file outside the store port only.** It would protect the file store
  and no other store; the port method lets a platform store use its own
  atomic primitive (a database transaction, a compare-and-swap).
- **Fail `recover` without keeping the freeze** (the previous behaviour).
  Rejected: it leaves a coordinator that is running on unrecorded state.

## The five questions

1. **Does this keep the trusted core small?** Yes. The only change outside the
   product crates' new code is the order in which the client exports its
   sessions; `tacenta-core` is untouched.
2. **Is the behaviour owned by a written specification?** By this record and
   the ones it amends. The byte layout of the snapshot does not change.
3. **Can the security claim be reproduced?** `group_client::tests` open a
   client that is stale, a client that is ahead and a client connected from the
   snapshot (with three peers, so the export order matters); two coordinators
   on one store, where the second is frozen and, after `recover`, sends without
   reusing a position; a failed `recover` after a store latch, which stays
   frozen; and `operation_store::tests` for the port, the handle and two file
   store handles racing on one file.
4. **Does it preserve wire compatibility with a named profile?** Yes. The
   exported state is the same bytes in a stable order.
5. **Is this protocol functionality, or product coupling trying to enter the
   core?** Product coordination.

## Why

The snapshot is the durable root only if what the process runs on is what the
snapshot holds. A check at `open` and a check at each commit are the two places
where a difference can be seen before it costs a message.

## What would reopen this

A supported multi-process profile (a shared store with a real lease), a
provider that exposes a cheap digest of its state, or a platform store whose
native compare-and-swap should replace the read in the provided implementation.
