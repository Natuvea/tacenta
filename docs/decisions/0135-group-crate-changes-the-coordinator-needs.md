# 0135 — group crate changes the coordinator needs

> Amends 0100, 0106, 0109, 0117, 0124, 0131, 0133, 0134, 0136 and 0138.

The client's coordinator (`GroupClient`, 0131) shipped with five workarounds
for behaviour of `tacenta-group`, and with its own copy of the sequence rule.
The group crate and the client were changed by separate lanes, so each
workaround was recorded as "needs a group-crate change". This record makes the
changes together, so the workarounds go.

## Decision

1. **The final attempt can be recorded as accepted.**
   `LogicalSend::record_relay_accepted` accepts a recipient that is
   `handed_off`, and also a recipient that is `exhausted_unknown`, a state the
   outbox reaches only through three reservations with the ciphertext stored, so
   the state itself implies both (the function does not test them again); the
   result is `relay_accepted`. `GroupOutbox::recover_from_transcript` accepts the `TCGA`
   record for either state and refuses it for every other. A fourth
   reservation is still refused before any relay request, and a recipient that
   is `exhausted_unknown` with no acceptance recorded stays that way, so
   nothing is ever recorded as accepted that the relay did not accept.
   The coordinator records acceptance of the final attempt in both outboxes
   (the application outbox and the control outbox, 0124) and no longer returns
   success while leaving the durable state at `exhausted_unknown`. This
   removes the trade-off stated in 0134, that the durable state understated a
   delivery.

2. **Recovery does not count sends a later cancellation made terminal.**
   `GroupOutbox::recover_from_transcript_at_revision(group_id, entries,
   applied_revision, payload_commitment)` replays the transcript and then
   applies `cancel_for_newer_roster(applied_revision)` once, the same value
   the caller applies after recovery today. While it replays, a send whose
   revision is below `applied_revision` does not count toward
   `MAX_LIVE_LOGICAL_SENDS`, because that cancellation ends it terminal.
   `recover_from_transcript` keeps its signature and means "no cancellation
   applied". The outbox that comes back equals the outbox that was running,
   including its applied revision. The client replays the whole transcript once
   instead of one logical send at a time.

3. **A roster view can start from a source roster at any revision.**
   `RosterView::accept_source(authenticated_authority, roster, digest)`
   starts a view from the source roster of an authenticated invitation
   bootstrap. It refuses a roster whose authority is not the authenticated
   one (`WrongAuthority`), a roster that does not list its authority
   (`MissingAuthorityMember`) and a closed roster (`InvalidSource`, a new
   refusal). At revision zero it applies the genesis rules exactly, so it
   agrees with `accept_genesis` there. The trust is the same as for a genesis
   roster: the roster arrived from the pinned authority's bootstrap channel,
   and the invitee has no earlier history to check its predecessor digest
   against. `GroupClient::join_group` takes a roster at any revision and uses
   this constructor, so an invitee admitted after the group has moved can join
   at the revision it was invited at.

4. **The canonical member order is public.** `Member::canonical_cmp` (identity
   bytes, then device bytes, 0136) is `pub`. The client sorts rosters and
   recipients with it in production code instead of a hand-written copy of the
   rule.

5. **A removed or closed member's receiver is restored, not replaced.**
   Decision 0139 made `GroupReceiver::decode_state` restore the receiver of a
   removed member or a closed group as a terminal state. The client no longer
   substitutes an inert receiver for it: `GroupClient::join_group` after a
   restart recovers the durable receiver in every case, so the stable event
   counter of a removed member survives a restart and a member that is
   readmitted continues its event IDs, and `GroupReceiver::status()` says
   `NotMember` or `Closed`. (A terminal receiver holds no accepted entries, so
   there is no dedup history to keep; the counter is the state the inert
   stand-in lost.)

6. **The client allocates sequences with `GroupOutbox::next_sequence`.**
   `GroupClient::send_group` computed the highest retained sequence itself,
   across every revision. It now asks the outbox, so the rule of 0138 has one
   owner and a sequence starts again at zero at each revision, as 0095 says.
   Compaction keeps every live send and the sixteen most recent terminal ones, so
   the newest send of the current revision is always retained and the retained
   maximum stays the high-water mark that 0138 requires. A send at an older
   revision is refused as stale, so a sequence dropped with an old revision's
   sends cannot be reused.

## Considered

- Keep the final attempt at `exhausted_unknown` and document it. That was the
  state of the branch before this record, and it understated a delivery the
  client had observed.
- Make the third reservation a marker that sends nothing. It cuts the retry
  budget of 0106 to two sends.
- For recovery, drop the live-cap check while replaying and check at the end.
  The end of `recover_from_transcript` is still before the caller's
  cancellation, so the check would fail the same way. The caller has to pass
  what it will apply.
- For recovery, keep the client's one-send-at-a-time replay. It works, but
  every caller of the group crate would have to rediscover it.
- Derive a view from a bootstrap only inside the invitation types. The view is
  a roster-progression value and the constructor belongs beside `accept_genesis`.
- Leave the member order private and keep the client's copies. The two would
  drift the next time the order changes.

## The five questions

1. **Does this keep the trusted core small?** Yes. All five changes are in
   product crates; `tacenta-core` is untouched.
2. **Is the behaviour owned by a written specification?** By this record and
   the records it amends. The Lean model has no relay-acceptance or recovery
   state, so items 1 and 2 are not modelled; item 3 has no model counterpart
   either. That is open and stated in `docs/claims.md`.
3. **Can the security claim be reproduced?** Tests in
   `crates/tacenta-group/tests/coordinator_needs.rs` (the five items),
   `crates/tacenta-client/src/tests/review_live.rs` (the final attempt in both
   outboxes) and `group_client::tests` (an invitee joining at a later revision,
   the ordering of `next_roster`, a removed member restarting with its own
   receiver). `tooling/run-group-chat-demo.sh` runs them and fails if one is
   renamed or removed.
4. **Does it preserve wire compatibility with a named profile?** Yes. No record
   layout changes: a `TCGA` record for a final attempt has the bytes it always
   had; older code refused to replay it, and nothing was released.
5. **Is this protocol functionality, or product coupling trying to enter the
   core?** Product policy. Nothing crosses into the core.

## Why

Each workaround was correct on its own and wrong as a standing rule. The
one-at-a-time replay hid a recovery failure the group crate still had (a group
that had run correctly could not be recovered once more than eight sends had
crossed a cancellation). The inert receiver threw away state the group crate
could now keep. Recording acceptance of the final attempt states what the
relay said. Making the order public removes the last place where two copies of
one rule could diverge.

## What would reopen this

A multi-device profile (the one-device rule in 0137 and the receiver key), a
per-recipient retry budget other than three, a bootstrap that carries the
source roster's predecessor chain so an invitee can verify it, or a receipt
protocol that lets an application confirm more than relay acceptance.
