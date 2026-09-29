# 0131 — staged group receive and its entry point

Amends 0096, 0098, 0099 and 0107, whose text described an acknowledgement
order the live client did not follow. Amended by 0135.

## Decision

The live group receive path is staged, one fetched item at a time and in
relay order:

1. fetch what the relay holds for the device (no acknowledgement);
2. decrypt the item with `CryptoProvider::decrypt_with_outcome`, which returns
   the plaintext, the pairwise-authenticated peer identity and the crypto state
   effect (`unchanged`, `advanced`, `terminal`);
3. export the provider state as it stands **immediately after that item** and
   commit one combined snapshot carrying that state and the item's group
   disposition (accepted, duplicate, deferred, terminal refusal, malformed,
   roster or invitation transition);
4. only when every item of a fetched prefix has a committed disposition, or
   needs none (an undecryptable item whose state effect is `unchanged`), send
   the cumulative acknowledgement for that prefix.

A crash between step 2 and step 3 therefore sends no acknowledgement: the relay
redelivers the item and the restored durable state decrypts it again. A commit
that is `failed` or `unknown` stops the batch at that item; the prefix committed
before it is acknowledged and returned, the item and everything after it are
not acknowledged.

The authenticated peer is always `Member::new(authenticated_peer, [device])`,
built from the provider outcome and the crypto-layer device of the routed
address (0107). No production code path accepts an identity or a state effect
from a caller. The helper that builds a `GroupReceiveInput` from bare bytes and
the `commit_*` variants that only tests call are compiled under `cfg(test)`.

**Entry point.** `group_client::GroupClient` (experimental, public, not in the
SDK surface manifest, not exported by any binding) takes a `Client` by value
together with an `OperationStore`, which it wraps in a `DurableStore` so that
every store latches (0134). It is the only owner of the mailbox and of the
pairwise state while it lives, so the plain `Client::receive`, `drain` and
`inbound` cannot be used to acknowledge group traffic ahead of a commit: the
compiler, not a flag, keeps them out. Its methods are the non-test callers of
the coordinator functions: `open`, `recover`, `create_group`, `join_group`,
`await_group`, `send_direct`, `receive`, `receive_next`, `send_group`,
`dispatch_pending_group_sends`, `install_roster`, `dispatch_pending_controls`,
`invite`, `accept_invitation` and `revoke_invitation`. The `commit_*` variants
that only tests call, and the GC-03 fault harness (a model of the acknowledgement
order over opaque bytes, which never touches a real provider or store), are
compiled under `cfg(test)`; the blanket `allow(dead_code)` on the coordinator
modules is gone. `open` on an empty store publishes the first snapshot with the
client's provider state, so the durable root exists before the first operation
(0132). A pin on the authority is kept by the coordinator: an invitation
bootstrap is recorded only from the pinned authority.

**What is still not reachable or not done, exactly.**

- An invitee does not derive its roster view inside the commit of the
  bootstrap record. The bootstrap is recorded (`await_group`, then `receive`)
  and reported with its source roster; the caller then attaches that source
  roster with `join_group`, which since 0135 accepts a roster at any revision
  (`RosterView::accept_source`), so an invitee invited after the group moved
  past genesis joins at the revision it was invited at. The caller, not the
  coordinator, decides to join from what the bootstrap reported.
- The receiver state of a member that a roster removed, or of a closed group,
  cannot be restored by the group crate (CR-06). `join_group` after a restart
  substitutes an inert receiver over the accepted roster for such a member,
  which refuses every application context as `not_active`, as it would have; its
  dedup history is not restored.
- The delivery cursor of the snapshot is written by nobody. An event returned by
  `receive` is committed before it is returned, but a crash between the commit
  and the caller's use of the event does not redeliver it: the relay redelivers
  the item, the durable provider state has already consumed its key, and the
  decrypt is refused. Redelivery of committed but unconsumed events (the
  GC-06 event-consumption boundary) is open, and so is the same window for a
  direct message (0132).
- If the cumulative acknowledgement itself fails (a transport error after every
  item of the prefix committed), `receive` returns that error and the events of
  that call are not returned to the caller. Nothing is lost durably: the relay
  redelivers the unacknowledged items, whose keys the durable state has
  consumed, so they are dropped and acknowledged by the next call. It is the
  same at-most-once window as the one above.
- The envelope `kind` is a routing label, not an authenticated field (see the
  amendment to 0116).
- Expiry is evaluated at the explicit logical time the caller passes; there is
  no clock mapping (GC-04, CR-17).

## Considered

- Keep `Client::receive` and add a hook the caller runs before the
  acknowledgement. Rejected: nothing forces the hook, which is how the old code
  drifted.
- Give `Client` an optional coordinator field and route `poll_batch` through it
  when set. Rejected: a runtime flag still leaves `drain` and `send` callable
  around the coordinator, and it grows the `Client` facade that the surface
  manifest tracks.
- A wrapper type that owns the client. Chosen: no bypass, no change to the
  facade, and the pairwise state has one owner (0132).

## The five questions

1. **Does this keep the trusted core small?** Yes. It calls
   `decrypt_with_outcome`, which the pinned core already provides, and adds
   nothing to the core.
2. **Is the behaviour owned by a written specification?** By this record and
   0098/0099/0107; the wire and state bytes stay product-owned (CR-12 in the
   review names the missing vectors for them; this record does not close it).
3. **Can the security claim be reproduced?** The live traces in
   `crates/tacenta-client` (`group_client::tests`) run a real provider, relay
   and directory: `a_crash_between_receive_and_commit_redelivers_the_group_message`,
   `recovery_resets_the_provider_state_so_the_redelivery_decrypts_again` and
   `the_live_receive_takes_the_peer_and_effect_from_the_provider_outcome`. The
   wrong-sender and wrong-device refusals there take their identity from the
   provider outcome.
4. **Does it preserve wire compatibility with a named profile?** Yes: no wire
   byte changes.
5. **Is this protocol functionality, or product coupling trying to enter the
   core?** Product coordination. The boundary is that the coordinator uses the
   seam's outcome type and nothing provider-specific.

## Why

The acknowledgement is the point after which the relay forgets the message. A
disposition that is committed later than the acknowledgement is not durable in
any sense a recovery can use, and the review's reproduction lost a roster
control that way. Exporting the provider state after each item, not once per
batch, is what keeps the durable state consistent with the acknowledged prefix:
a batch-level export would record ratchet steps for items whose dispositions had
not been committed, and their redelivery could no longer decrypt.

## What would reopen this

A store that can commit only per batch, a relay that acknowledges per item, or a
consumption callback from the application (which would move the acknowledgement
of application events after the caller has them).
