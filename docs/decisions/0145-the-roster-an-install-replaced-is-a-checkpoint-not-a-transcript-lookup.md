# 0145 — the roster an install replaced is a checkpoint, not a lookup in the control transcript

> Amends 0141.

0141 lets `install_roster` tell the member an install removes, wherever that
member is listed, by finding the roster the installed successor replaced: the
successor names its predecessor's digest, and the predecessor's preimage was
looked up in the roster records (`TCGC`) that the snapshot keeps in
`group_controls` (0122). A verification of the second fix round showed that the
lookup can be broken by a peer that is not in the group.

## The failure

Every roster payload the authority's coordinator decrypts writes a `TCGC`
record: from any sender, whatever the disposition, including a control that the
roster view refuses as `WrongAuthority`. The snapshot keeps 64 control records
(0133) and evicts the oldest, and each such payload also writes an effect
record, so about 30 payloads from a registered peer that knows the group ID and
the authority's route replace the record of the roster that the next install
will replace. Reproduced through `GroupClient` with a real provider and relay:

| controls from the stranger | install of a removal, removed member listed last | retry |
|---|---|---|
| 28 | `delivered 3` | `delivered 3` |
| 30 | `delivered 2, unprepared 1`; the removed member is never told | `Err(Policy)` |
| 1,000 | `delivered 2, unprepared 1` | `Err(Policy)` |

With the removed member listed first the first call still delivers to all three,
because the install and the first recipient's control are one commit, and the
retry is refused. This is the failure 0141 was written to end (N2), now
triggered by any registered peer instead of by list order.

0141 also said an evicted predecessor means "the call is refused up front". The
first call was not: the up-front check admits the members of the roster being
replaced, and only the check made after the install needed the lost record, so
the call installed the successor, told the members it could, and reported the
rest as `unprepared`. Only a retry, when the successor was already installed,
was refused up front.

## Decision

1. **The roster an accepted successor replaced is kept in its own checkpoint,
   `TCGS`.** The record holds the group ID and the preimage of the roster that
   the view held before the transition, and is written in the same commit as the
   accepted transition itself (`commit_roster_transition`, whichever path
   reached it: a control from the wire, `install_roster`, or a held control being
   applied). It is a checkpoint of the kind 0133 defined for the view, the
   invitation book, the control outbox, the cancellation record and the held
   controls: a new one replaces the previous one of its group whole, and the
   64-record bound never evicts the latest. Its size is one roster (at most
   3,048 bytes for eight members, 4,096 as the codec bound) and 24 bytes of
   framing, once. It cannot grow with the number of installs or with anything a
   peer sends.

2. **`replaced_roster_members` reads only that record.** It accepts it when the
   record is for the attached group, its bytes decode as a roster and their
   commitment is the `predecessor_digest` of the view's accepted roster, and
   otherwise returns nothing. The roster records (`TCGC`) stay what 0122 made
   them, a bounded transcript; nothing authorises anything from them.

3. **The first call and its retry now agree.** The members the install may tell
   are the same set before and after the successor is installed, because the
   commit that installs it writes the record that names them. A view that a
   transition produced never lacks its replaced roster; only a view that was
   attached from a caller's roster does (point 4). The `unprepared` result keeps
   the causes 0141 listed that remain (a transient failure while preparing, a
   full control outbox).

4. **A view with no checkpoint covers nobody, and the call is refused whole.** A
   view that was attached from a roster the caller passed (`join_group` at a
   later revision) or a snapshot with no `TCGS` record has no replaced roster.
   An `install_roster` for the installed successor that lists a member outside
   the view's roster is `Policy`, before anything is committed, exactly as
   before. The snapshot layout changes by one record kind; no snapshot written by
   `GroupClient` exists outside the branch that introduced it.

## Considered

- **Stop writing `TCGC` for controls the view refuses.** It would stop this
  flood and no other: a run of accepted controls from the authority (any group
  with many installs while one install is being retried) also pushes the record
  out, and the transcript is the evidence that a control was seen and refused
  (0122). Rejected.
- **Exempt the predecessor's `TCGC` record from eviction.** It needs the view at
  the point of eviction, which the append function does not have, and it keeps a
  variable-length transcript record alive by its content. A checkpoint is the
  same idea with a fixed place. Rejected.
- **A larger transcript.** Finite; the flood is sized by the attacker. Rejected.
- **Keep every replaced roster.** Unbounded, and 0141 promises only the
  immediate predecessor. Rejected.
- **A per-sender quota on transcript records.** New state and a new rule for a
  problem the checkpoint removes at the source. Rejected.

## Limits this record leaves, exactly

- Only the immediate predecessor's members are covered. A member removed two
  installs ago cannot be told by this call (0141).
- A removed member that never receives the control is not followed up: there is
  no catch-up or acknowledgement protocol (0142).
- A peer that is not in the group can still fill the control transcript and make
  every junk message cost a whole-snapshot rewrite (`docs/claims.md`); it can no
  longer take away anything an install needs.
- The checkpoint is a decrypted roster in the unsealed snapshot. The snapshot
  already holds the accepted roster (`TCGV`) and, until this record, the replaced
  roster in the transcript.
- The snapshot grows by the checkpoint: 489 bytes at eight members
  (`docs/reproduce.md` has the measured sizes).

## The five questions

1. **Does this keep the trusted core small?** Yes. Product coordination only.
2. **Is the behaviour owned by a written specification?** By this record and the
   ones it amends. The `TCGS` layout is product-owned and has no vector, like the
   other `TCG*` records (`docs/claims.md`).
3. **Can the security claim be reproduced?** `group_client::tests::stranger_traffic`
   floods the authority with 0, 28, 30 and 1,000 controls from a registered
   stranger and then removes a member with the removed member listed first and
   last: the first call and the retry both report everyone delivered and the
   removed member learns it is out. Another test floods 100 controls, stops an
   install half way and restarts. A third removes the checkpoint and expects the
   call to be refused whole with nothing committed. `group_operations` unit tests
   pin the eviction exemption and the read.
4. **Does it preserve wire compatibility with a named profile?** Yes. No wire
   bytes change; the snapshot gains one record kind.
5. **Is this protocol functionality, or product coupling trying to enter the
   core?** Product coordination.

## Why

An authorisation decision that depends on a record a stranger can push out is a
decision the stranger can change. The information was already known at the moment
it mattered, in the commit that installs the successor, so it is kept there, in
the one place that commit already owns.

## What would reopen this

A receipt or catch-up protocol, a requirement to tell members removed more than
one revision ago, or a multi-device profile in which the replaced roster is not
one value.
