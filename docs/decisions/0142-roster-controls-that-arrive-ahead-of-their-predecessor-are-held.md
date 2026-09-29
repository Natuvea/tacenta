# 0142 — roster controls that arrive ahead of their predecessor are held, not refused

> Amends 0102, 0114, 0124 and 0139. Amended by 0146 (points 2 and 4).

The authority fans a roster successor out to each member as a separate pairwise
message (0124). Nothing orders those messages across recipients, across retries
or against the invitation bootstrap, and a member that cannot apply a control
had no way to keep it: `RosterView::accept_successor` answers
`MissingPredecessor` when the control is more than one revision ahead, the
answer is terminal, and the message has already been consumed and acknowledged.
A member that misses or receives out of order one control could never follow the
group again. Three ordinary sequences reproduced it.

## The failures this prevents

1. **A bootstrap and a successor in one batch (N3).** A pending invitee receives
   the invitation bootstrap and, right behind it, the roster that admits it. It
   has no roster view until the caller reads the bootstrap and calls `join_group`,
   which is after the batch, so the successor was refused and acknowledged. The
   next successor then answered `MissingPredecessor` for good.
2. **A retried older control arrives after a newer one (N4).** Revision 2 was
   prepared for a member and not sent (a relay refusal), revision 3 was installed
   and delivered, and the retry of revision 2 arrived last. The member ended at
   revision 2 while the authority was at 3.
3. **The first message of a just-admitted member overtakes the roster (N5).**
   The authority admits Carol at revision 2 and tells her first; Carol writes to
   Bob at revision 2 before Bob has the roster. Bob's receiver answered
   `NotActive` (Carol is not in revision 1) and consumed a legitimate message.

## Decision

1. **A roster control that is ahead of the view is held.** The coordinator keeps
   a bounded, durable queue of at most **4** roster controls (the `TCGQ`
   checkpoint record, replaced whole by each commit like the other checkpoints
   of 0133, at most about 12 KB). A control is held when it comes from the
   pinned authority for the attached group, the group crate refused it with
   `MissingPredecessor` **because it is more than one revision ahead** (revision
   at least two above the view's), it is at most four revisions past the
   next one, and no different control for that revision is already held. It is
   committed in the same snapshot as the provider state that consumed it and the
   disposition, so a crash cannot consume the message without keeping it. The
   outcome is `GroupOutcome::RosterDeferred`.
   A control one revision ahead whose predecessor digest does not match is a
   fork and stays a terminal refusal.

2. **A coordinator that has no view yet holds the controls it is sent.** After
   `await_group` the pinned authority and the group are known but not the roster.
   A roster control from the pinned authority for that group is held (the same
   queue, at most four, no window because the base revision is unknown; when
   it is full a lower revision takes the highest one's place, 0146), and the
   `join_group` that gives the coordinator its view applies it. That is what the
   bootstrap-plus-successor batch needs.

3. **The queue drains whenever the view advances.** After a control is accepted
   from the wire, and after `join_group`, `create_group`, a restart or a
   `recover` has given the coordinator a view, any held control that is now the
   successor of the view (revision plus one, predecessor digest equal to the
   view's) is applied in its own commit with exactly the checks a control from
   the wire gets, and the events it unlocks are committed like any roster's. The
   commit also drops every held control the view has passed. Draining is
   repeated until nothing applies. A held control that the view then refuses for
   another reason is dropped by the commit that refused it. Because the queue is
   durable and draining is idempotent, a crash between two of these commits is
   finished by the next attach;
   `drain_faults_and_receiver_schedule::a_fault_at_every_commit_of_a_reverse_order_drain_still_converges`
   fails a commit of each kind at each of the first twelve commits of a drain, in
   three arrival orders (108 runs), and every run ends at the last revision with
   nothing held, before and after a restart.

4. **A future application context from a sender the roster does not yet list is
   deferred.** `GroupReceiver::receive` judged the sender's activity against the
   current roster before it looked at the revision, so a context for revision
   `r + 1` or `r + 2` from a member that roster `r + 1` admits was `NotActive`.
   The revision comes first now: a context ahead of the accepted roster, within
   the two-revision window, is deferred whoever the sender is, and revalidation
   against the roster that arrives decides it (0102), exactly as it does for a
   sender that is already listed. Deferral of such senders is limited to **2**
   of the 4 deferred slots and, since 0146, to one per identity. (As first
   written this sentence went on to say that a peer that is not in the group
   could not use up the room a member's early message needs. One such peer
   could, by sending two contexts; two still can, and 0146 states that limit.)
   The receiver's state codec accepts up to two deferred contexts whose sender
   the roster does not list (it required every deferred sender to be listed),
   from two identities (0146). The local member must still be active to defer
   anything (a terminal receiver, 0139, holds nothing).

## Limits this record leaves, exactly

- **There is still no catch-up.** A control that is never delivered (dropped by
  the relay, a recipient device that was offline past the relay's retention, an
  authority that abandons it) leaves the member behind, and nothing asks for it
  again. The authority's control outbox records relay acceptance, not receipt.
  Adding a request for a missing revision, or a receipt, is a new protocol
  element; this record does not invent one.
- A member more than **five revisions** behind (past the four-revision window)
  has the further controls refused, as before, and needs a new invitation.
- A control held while the coordinator has no view is applied only if the
  source roster the caller joins from is the predecessor it names; held controls
  the joined roster has already passed are dropped.
- **Two registered identities can still take both slots that are open to
  senders the roster does not list**, and the first message of a just-admitted
  member is then refused and lost (0146). A coordinator with no view reaches at
  most four revisions past its source roster from what it was sent (0146).
- **A pending invitee's early application message is still lost.** The receiver
  of a member that is not in the current roster is a terminal state (0139) and
  holds nothing, so a message from another member for the revision that admits it
  is `NotActive` if it beats the roster to the invitee. Only the authority tells
  an invitee first in the sequences tested; the reverse race is open.
- The authority is trusted to send a consistent chain. Two different controls for
  one revision are a fork: the second is refused and the first is kept.
- The queue holds controls from the pinned authority only, so a peer that is not
  the authority cannot fill it. It holds decrypted roster preimages until they
  apply or the view passes them, in the unsealed snapshot.

## Considered

- **Make the sender order its controls per recipient** (send revision 2 before 3
  and never 3 while 2 is outstanding). It fixes the retry order (2) and nothing
  else: the bootstrap batch (1) and the additive race (3) are receive-side
  orderings the sender does not control.
- **Acknowledge nothing that could still become valid.** The message cannot be
  redelivered by the relay: its key is consumed as soon as it is decrypted, so
  not acknowledging it only makes the relay resend a ciphertext that no longer
  decrypts. What must be kept is the decrypted control, and that is the queue.
- **Derive the invitee's view in the commit of the bootstrap** and so remove the
  view-less case. It also makes joining automatic instead of the application's
  decision, and it does not help the retry order (2).
- **A catch-up request path** (member asks the authority for the controls it is
  missing, bounded). Sound, and the only remedy for a control that never arrives,
  but a new message type, a new authorization rule and a new bound; it needs its
  own record and specification.
- **Defer at the group crate's view** (`RosterView` keeps successors). It would
  change the model the Lean file describes (a view is a single checkpoint); the
  client holds the controls the view refuses instead, and the group crate's
  refusal stays exactly what the model says.
- **For the additive race, refuse it and document it.** Possible, but the message
  is legitimate and the receiver already has the mechanism.

## The five questions

1. **Does this keep the trusted core small?** Yes. Product coordination and
   product policy; the core is untouched.
2. **Is the behaviour owned by a written specification?** By this record. The Lean
   model has no receiver and no queue, and the `RosterView` rules it describes are
   unchanged.
3. **Can the security claim be reproduced?** `group_client::tests::roster_fanout`
   runs the three sequences through a real provider and relay (the invitee's
   batch, the retried older control, the admitted member's first message), the
   window and the capacity, a restart with a held control, a control that is not
   from the authority, and the crash-between-commits recovery
   (`a_fault_at_every_commit_of_a_reverse_order_drain_still_converges`, 108 runs); the group crate's
   `tests/limits.rs` and unit tests pin the two-slot bound for unlisted senders
   and the codec.
4. **Does it preserve wire compatibility with a named profile?** Yes. No wire
   bytes change. The snapshot gains one record kind (`TCGQ`); the receiver state
   layout is unchanged and accepts a superset.
5. **Is this protocol functionality, or product coupling trying to enter the
   core?** Product coordination.

## Why

A membership change that a member can miss without recourse turns every network
hiccup into a permanent split. The smallest thing that removes the three
reproduced splits keeps the decrypted control until the chain reaches it, with
bounds that make the queue as hostile-proof as the receiver's own. What it cannot
remove is a control that never arrives, and the record says so.

## What would reopen this

A receipt or catch-up protocol; a multi-authority or multi-device profile (the
chain is no longer linear); a relay that reorders more than the window; or a
measured group in which controls lag by more than five revisions.
