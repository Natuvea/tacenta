# 0127 — staged group receive and its entry point

Amends 0096, 0098, 0099 and 0107, whose text described an acknowledgement
order the live client did not follow.

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
together with an `OperationStore`. It is the only owner of the mailbox and of
the pairwise state while it lives, so the plain `Client::receive`,
`drain` and `inbound` cannot be used to acknowledge group traffic ahead of a
commit: the compiler, not a flag, keeps them out. Its methods are the
non-test callers of the coordinator functions: `open`, `recover`,
`create_group`, `join_group`, `await_group`, `send_direct`, `receive`,
`send_group`, `install_roster`, `dispatch_control`, `invite`,
`accept_invitation`, `revoke_invitation`.

**What is still not reachable, exactly.**

- A member whose source roster is not revision zero cannot derive a
  `RosterView` from an invitation bootstrap: the group crate constructs a view
  only from a genesis roster or from a serialized checkpoint. Such a bootstrap
  is recorded and refused as unusable (a group-crate follow-up is named in the
  report).
- The delivery cursor of the snapshot is written by nobody. An event returned by
  `receive` is committed before it is returned, but a crash between the commit
  and the caller's use of the event does not redeliver it: the relay redelivers
  the item, the durable provider state has already consumed its key, and the
  decrypt is refused. Redelivery of committed but unconsumed events (the
  GC-06 event-consumption boundary) is open.
- The server-visible `kind` is a routing label, not an authenticated field
  (see the amendment to 0116).

## Considered

- Keep `Client::receive` and add a hook the caller runs before the
  acknowledgement. Rejected: nothing forces the hook, which is how the old code
  drifted.
- Give `Client` an optional coordinator field and route `poll_batch` through it
  when set. Rejected: a runtime flag still leaves `drain` and `send` callable
  around the coordinator, and it grows the `Client` facade that the surface
  manifest tracks.
- A wrapper type that owns the client. Chosen: no bypass, no change to the
  facade, and the pairwise state has one owner (0128).

## The five questions

1. **Does this keep the trusted core small?** Yes. It calls
   `decrypt_with_outcome`, which the pinned core already provides, and adds
   nothing to the core.
2. **Is the behaviour owned by a written specification?** By this record and
   0098/0099/0107; the wire and state bytes stay product-owned (CR-12 in the
   review names the missing vectors for them; this record does not close it).
3. **Can the security claim be reproduced?** The live traces in
   `crates/tacenta-client` (`group_client::tests`) run a real provider, relay
   and directory; the wrong-sender and wrong-device refusals there take their
   identity from the provider outcome.
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
