# 0133 — bounded operation snapshot and control-outbox reclamation

Amends 0099, 0103, 0107, 0113, 0122 and 0124. Amended by 0135, 0144 and 0145.

## Decision

Every collection of the operation snapshot has a literal bound, and the bounds
hold for traffic from any peer that can open a pairwise session, not only for
group members.

| Collection | Bound |
|---|---|
| `group_controls` | 64 records (unchanged from 0122), and at most one each of the checkpoint records `TCGV`, `TCGB`, `TCGO`, `TCGX` and, since 0142 and 0145, `TCGQ` (the held roster controls) and `TCGS` (the roster the accepted roster replaced): a new checkpoint replaces the previous one of its kind in the same candidate snapshot |
| `inbox` | 64 records, newest kept |
| `dedup` | 512 entries, newest kept. An entry is the 32-byte payload commitment of an accepted context; 512 is 8 members times the 64-sequence window of 0113, the most the receiver itself can retain |
| `outbox` | the records of at most 8 live logical sends (0103) and of the 16 most recent terminal logical sends. When a commit leaves more terminal sends, the records of the oldest are dropped in that same commit |
| control outbox (`TCGO` state) | at most 8 live handoffs (`prepared`, `handed_off`) and at most 16 retained terminal handoffs (`relay_accepted`, `exhausted_unknown`, `cancelled`, `cancelled_after_handoff`), so at most 24 entries |

Terminal control handoffs are reclaimed. A control handoff counts against the
live bound only until it is terminal; the oldest terminal entries beyond 16 are
dropped when a preparation or a transition leaves more (age is an allocation
sequence stored with each entry; the state format is `... State v2`, the group
experiment being unreleased so v1 is not read). The full ciphertext is retained
for the terminal entries that remain, which is the evidence 0126 requires for a
cancelled control.

Plaintext that failed authentication or parsing is not retained. A malformed or
refused group payload leaves a `TCGM` record of exactly 41 bytes: the tag, the
state effect, the plaintext length as a big-endian `u32`, and its 32-byte
payload commitment. A `TCGR` receive record carries the encoded application context
only for an accepted context (at most the 2,048-byte context bound of 0104);
for duplicate, deferred and refused dispositions it carries the commitment and
the disposition and no context bytes. The receiver's own bounded state
(`application_state`, 0113 and 0114) remains the authority for deduplication
and deferral; the `inbox` and `dedup` collections are audit records, and no
recovery reads them. (Since 0144 the delivery path reads the accepted contexts
of `inbox` to redeliver events the caller has not acknowledged, and the record
of a delivered event is rewritten without its context.)

The application outbox transcript is recovered by the group crate with the
latest cancellation passed in (0135): a send that cancellation ends terminal
does not count toward the live cap of eight while the transcript replays, and
the cancellation is applied once afterwards. Before 0135 the client replayed
one logical send at a time to get the same result, because the group crate's
whole-transcript replay cancelled only afterwards, so sends that a roster change
had already cancelled still counted toward the live cap of eight, and a group
with more than eight sends across a cancellation could not be recovered even
though it had been running correctly. That defect existed before this record;
the compaction above depends on the replay, so it was worked around here and is
fixed in the group crate by 0135.

The control outbox refuses the ninth live handoff with an explicit
`outbox_full`, exactly as the application outbox refuses the ninth live send.
A refusal happens before any pairwise encryption (0134), so it never burns
ratchet state.

**Reachability of the eight-member profile.** With these rules an authority can
grow a group from one to eight members through the coordinator and deliver every
roster control: the largest single fan-out is seven recipients, which is below
the live bound of eight. The test grows a live group from 1 to 8 members with
every control handoff dispatched.

## Considered

- Keep the lifetime cap of eight control handoffs. Rejected: reproduced at head,
  the ninth control send after four membership changes fails after the ratchet
  advanced and the roster had already moved on, so a group wedged at five
  members and the eight-member profile of 0092 was unreachable.
- Delete every terminal control entry at once. Rejected: 0126 asks that a
  cancelled control keep its ciphertext as evidence.
- Cap by bytes rather than by count. Rejected for now: a count is testable with
  a literal, and each record already has its own byte bound.
- Drop the oldest records of `outbox` regardless of the send they belong to.
  Rejected: the transcript is replayed from its `TCGI` record, so a send is kept
  or dropped whole.

## Trade-offs, stated

- Evidence for a terminal logical send older than the 16 most recent, and for a
  terminal control handoff older than the 16 most recent, is not kept locally.
  The guards that decide whether a control may be prepared (recipient
  authorization, invitation status, roster acceptance) are independent of that
  evidence; the evidence itself, not a decision, is what is dropped.
- The snapshot is still rewritten whole on every commit, so its size is its
  per-commit cost, and the bounds above are on record counts and on the size of
  each record, not on the snapshot in bytes. Measured (`docs/reproduce.md`): at
  eight members the first send from an empty outbox leaves a snapshot of about
  372 KB, of which 259 KB is provider state; after seventeen sends, with sixteen
  terminal sends retained, it is 1.73 MB, of which the provider state is still
  259 KB and the receiver state (bounded to 256 KiB by 0114) is 589 bytes, so
  about 1.47 MB is the outbox and the other collections. (As first written this
  bullet said they "stay in the low hundreds of kilobytes"; the steady state does
  not.)
- Records that older ADRs describe as retained "in durable storage" without a
  bound are now retained under the bounds above.

## The five questions

1. **Does this keep the trusted core small?** Yes; product state only.
2. **Is the behaviour owned by a written specification?** This record; the
   record grammar is product-owned and still has no vectors (CR-12).
3. **Can the security claim be reproduced?** Tests use these literals directly:
   64, 512, 8, 16, 24 and 41, none derived from a constant.
4. **Does it preserve wire compatibility with a named profile?** No wire bytes
   change. The unreleased control-outbox state format moves to v2.
5. **Product coupling entering the core?** No.

## Why

A snapshot that grows with the traffic of any pairwise peer turns ordinary
mail into local storage exhaustion, and an outbox that never forgets a finished
handoff turns finished work into a permanent refusal. Bounding both by the
number of live and of retained terminal records fixes the two together and keeps
the evidence that recovery and review actually use.

## What would reopen this

A measured profile that needs more than eight concurrent live control handoffs
(a larger roster, or several groups per client), a byte-denominated store
budget, or a journaled store that makes per-record retention cheap.
