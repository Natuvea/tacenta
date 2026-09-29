# 0132 — one durable root for pairwise state

Amends 0098 ("recovery never rewinds pairwise state") and 0091. Amended by 0143 and 0147.

## Decision

While a `GroupClient` owns a client, the operation snapshot's `provider_state`
is the only durable copy of that client's pairwise state, and **every** change
of that state is committed to it before the change has an external effect:

- a group send, a control send and a group receive commit the exported state
  with their own records, as before;
- a direct message send encrypts, exports the state, commits a snapshot that
  carries it, and only then puts the ciphertext on the wire. A commit that is
  not `committed` dispatches nothing;
- a direct message receive decrypts, exports the state after that item,
  commits it, and only then lets the item count toward the acknowledged prefix.

`GroupClient::send_direct` is the direct-message call for such a client. The
plain `Client::send` and `Client::receive` are not reachable on it (0131).
A client that has no `GroupClient` behaves exactly as before.

**The failure this prevents.** A direct message and a group message share one
pairwise ratchet. Before this record only group operations wrote to the
snapshot, so after `group send 0, DM, restart from snapshot.provider_state,
group send 1` the restored state had not seen the DM and encrypted group send 1
under the message number the DM had already used. The relay accepted the send
and the recipient could not decrypt it: reproduced at head as "second group
message received by bob: without a DM 1, with an interleaved DM 0", which is
also a reuse of one message key for two plaintexts.

## Considered

- **Write-through of provider state on every pairwise operation** (chosen).
- Refuse direct messages on a session a coordinator owns. Rejected: a peer can
  still send one, and refusing our own sends removes a product function to
  avoid a state-persistence gap.
- Persist only a per-session message counter beside the snapshot. Rejected: the
  ratchet state is the provider's, and a counter would need a provider change
  and a second durable root.
- Rely on the secure-store counter of 0078. Rejected as the fix: it is opt-in,
  it detects a rewound state rather than preventing one, and the native
  reference store attaches none.

## Trade-offs, stated

- Each direct send and each received direct item rewrites the whole snapshot.
  The measured commit cost is fsync-dominated (about 8 ms) at a 190 to 430 KB
  snapshot (the size of the first send from an empty outbox; the commit latency of
  a snapshot of a group in use, about four times larger, was not measured,
  `docs/reproduce.md`), so a direct exchange now costs one commit per message where it cost
  none. This is the price of a single root; a journal would lower it (0091).
- Under a `GroupClient`, application delivery of a direct message is
  at-most-once, with a window: the state commit precedes the acknowledgement,
  and the plaintext is returned after the acknowledgement. A crash between the
  commit and the caller's use of the plaintext loses that message, because the
  redelivered ciphertext can no longer decrypt. Without a `GroupClient` the same
  message is lost only if the caller has not saved state; that case is not
  changed. Persisting direct plaintext until the caller consumes it is not part
  of this record and is open.
- The secure-store counter of 0078 is still advanced by the same calls, on the
  same fail-closed (send) and best-effort (receive) rules.
- **One writer.** The single root is single only if one coordinator writes it.
  A second coordinator on the same store (an application and an extension, a
  restored backup run beside the original) encrypts at a ratchet position the
  first has already used, and the peer loses one of the two messages
  (reproduced: 1 of 2 received). Since 0143 the second writer's commit is
  refused and the coordinator freezes, so what it encrypted is not sent and the
  position is not reused on the wire. It can still encrypt at a used position
  in memory before the commit, and the provided `commit_after` is
  read-then-write (0143); `recover` adopts a newer snapshot and, since 0147,
  refuses one that is older than what the coordinator committed. That is a
  fence, not a supported configuration. `GroupClient::open` also refuses a client whose
  state is not the snapshot's (0143). One writer per store remains a
  precondition, stated in `docs/claims.md` and in the module documentation of
  `group_client`.

## The five questions

1. **Does this keep the trusted core small?** Yes; it calls the existing
   `export_state` and `encrypt`.
2. **Is the behaviour owned by a written specification?** This record.
3. **Can the security claim be reproduced?** `group_client::tests::
   a_direct_message_between_group_commits_survives_a_restart` runs the sequence
   above against a real relay and provider, with and without the interleaved
   direct message, and requires the second group message to be received in both.
   With the write-through removed it receives 0 where 1 is expected, the number
   the review recorded. `a_received_direct_message_is_committed_before_it_is_acknowledged`
   covers the receive side.
4. **Does it preserve wire compatibility with a named profile?** Yes; no wire
   byte changes.
5. **Product coupling entering the core?** No; nothing in the core changes.

## Why

The state that must survive a restart is the state the peer has already
observed us advance. Two roots that each capture part of it will disagree, and
the disagreement shows up as a lost or reused message on the sender.

## What would reopen this

Multiple processes writing one snapshot, a provider that exposes a cheaper
per-message durable counter, or a measured direct-message load for which a
whole-snapshot commit per message is too slow.
