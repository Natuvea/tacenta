# 0134 — freeze latch, monotonic generations, validate before encrypt

Amends 0091, 0098, 0106, 0117 and 0124. Amended by 0135.

## Decision

**Freeze is a latch.** Any commit that is not `committed` (`failed` or
`unknown`) latches the store the coordinator holds: `GroupClient::open` wraps
every `OperationStore` it is given in a `DurableStore`, so no store escapes it.
The free functions of `group_operations` take any store and latch only when the
store does; a plain test store does not. While it is latched no
snapshot is published, no pairwise operation starts and no dispatch happens:
every preparation, reservation, dispatch and receive returns `frozen` before it
encrypts, decrypts or sends. The latch is cleared only by `recover`, which reads
the store's durable snapshot, rebuilds every in-memory value from it, resets the
client's provider state to the recovered `provider_state`, and only then lets
operations resume. The in-memory provider state that a frozen operation had
already advanced is discarded by that reset; the ciphertext it produced was never
recorded and never left the process.

**Generations are monotonic.** A candidate snapshot's generation is
`max(current, highest generation ever attempted) + 1`. After an `unknown` write
(which may have landed) the next attempt therefore uses a higher generation
than the one that was in doubt, and recovery raises the floor to the recovered
generation. Two different snapshots are never published under one generation.

**Nothing that can refuse runs after an encryption.** Every check that can turn
a preparation into `policy` is evaluated first, on a dry run of the same commit
logic against a store that discards, and only then does the coordinator encrypt.
This covers a cancelled or already-terminal recipient, an existing prepared
handoff (returned as it is, never re-encrypted), a full control outbox, a
recipient that may not receive the control, an admission target missing from
the successor, and a revoked admission. A refusal leaves the provider state
byte-for-byte unchanged.

**The final attempt.** A recipient gets at most three handoff reservations, in
the application outbox and in the control outbox alike (0124). The third
reservation records `exhausted_unknown` before the bytes are sent, and the
coordinator sends that third and final attempt once. A relay acceptance of the
final attempt is returned as success and is **not** recorded as
`relay_accepted`: the group crate's state machine records acceptance only from
`handed_off`, and the coordinator does not write a record its own recovery would
refuse. The durable disposition therefore stays `exhausted_unknown` ("delivery
unknown, no more retries"), which understates a delivery that happened and never
overstates one. A fourth request is refused before any relay request. Before
this record the application outbox sent the third attempt and then returned
`policy` after the relay had accepted it, while the control outbox allowed a
third `handed_off` attempt and exhausted only on a fourth request; both now
follow the rule above.

## Considered

- Latch only on `unknown` and let `failed` retry. Rejected: 0098 freezes on both,
  and a failed write after an encryption leaves an unrecorded ratchet step just
  as an unknown one does.
- Latch inside each `commit_*` function. Rejected: the functions are given the
  store and the snapshot, not a place to keep a latch; the latch belongs to the
  store handle, so a caller cannot forget it.
- Make the third attempt a non-dispatch marker. Rejected: it silently reduces
  the retry budget documented in 0124 to two sends.
- Record acceptance of the final attempt. Needs a group-crate change
  (`record_relay_accepted` from `exhausted_unknown` when three attempts are
  reserved, and the matching `TCGA` recovery, which today requires
  `handed_off`); named in the report, not done here.

## The five questions

1. **Does this keep the trusted core small?** Yes; product state only.
2. **Is the behaviour owned by a written specification?** This record.
3. **Can the security claim be reproduced?** Tests: a second preparation after
   `frozen` neither succeeds nor changes the provider state; generations in a
   scripted store strictly increase across an unknown write; a refused
   preparation leaves the exported state identical; the third attempt is
   delivered once, returned `ok`, and a fourth is refused with no relay request.
4. **Does it preserve wire compatibility with a named profile?** Yes; no wire
   change.
5. **Product coupling entering the core?** No.

## Why

A write whose outcome is unknown can be the newest durable state or not exist.
Until recovery selects one, any new work builds on a guess. Encrypting before
validating turns a policy refusal into an unrecorded advance of the ratchet, which
is harmless to secrecy but wastes message numbers and desynchronizes what was
sent from what is recorded.

## What would reopen this

A store that can report the outcome of a specific generation without a full
recovery, or a group-crate state machine that records acceptance of the final
attempt.
