# 0146 — deferral slots are per unlisted identity, and the view-less queue keeps the lowest revisions

> Amends 0142.

A verification of the second fix round found three places where 0142 says more
than the code does, or stops short of what it needs. This record fixes two and
states the third.

## The failures

1. **A stranger takes the room a just-admitted member needs (N5 again).** 0142
   point 4 defers a future application context whoever sends it, limits senders
   the accepted roster does not list to two of the four deferred slots "so a peer
   that is not in the group cannot use up the room a member's early message
   needs", and stops there. A member the next roster admits is unlisted by
   construction, so it shares those two slots with any registered peer that knows
   the group ID and the recipient's route. One such peer sends two contexts for
   the next revision, fills both, and the admitted member's first message is
   refused `DeferredFull` and consumed. Reproduced through `GroupClient`: Bob's
   outcomes were `[Deferred, Deferred, Rejected(DeferredFull)]`, Carol's message
   was lost, and Bob showed no event when the roster arrived.
2. **The view-less queue can refuse the predecessor its controls need.** A
   coordinator with no roster view (a pending invitee before `join_group`) holds
   any four controls of the pinned authority. When revisions 3 to 6 arrive first,
   revision 2 is refused for want of room and consumed; after `join_group` at
   revision 1 the member sits there with `[3, 4, 5, 6]` held and nothing that can
   apply them. With a view the window `view + 2 ..= view + 5` always leaves the
   next revision to be applied on arrival, so the case cannot arise there.
3. **A held removal does not stop the holder from sending to the removed
   member.** A member that holds revision 3, which removes Carol, because
   revision 2 is missing is at revision 1 and sends to the members that view
   lists, Carol included.

## Decision

1. **One deferred context per unlisted identity.** A future application context
   whose sender the accepted roster does not list is deferred only if no context
   from the same identity is already deferred (the identity key, not the
   identity-and-device pair: a second device of one identity shares the quota),
   and only while fewer than two such contexts are held, as before. Otherwise it
   is refused `DeferredFull`, as a full queue refuses. An exact repeat of the held
   context reuses its slot. The receiver state codec holds the same rule: a state
   with two deferred contexts from one unlisted identity is `Conflict`. Listed
   senders are unaffected (two of the four slots stay theirs).

2. **What this does not do, exactly.** Nothing that a member has before the
   roster arrives tells a just-admitted member from any other registered peer.
   Membership is defined by the roster, and the roster is what has not arrived.
   The pairwise session authenticates an identity, not its membership. The
   invitation book is the authority's and the invitee's, not the other members';
   a held control (point 3 of 0142) names a future member only when the chain up
   to it is held, which it is not when the very next revision is what is missing.
   The rule therefore does not protect the admitted member's first message
   against two registered identities that each send one context for the next
   revision: both slots fill, Carol's message is `DeferredFull`, and it is lost.
   What the rule does is stop **one** peer from doing it alone, and make the
   attacker refill both slots with two accounts after every roster arrival, which
   frees them. A test pins the two-identity case as the limit it is. No protocol
   element is invented to close it. It costs one thing: a just-admitted member's
   **second** early message, sent before the roster arrives, is refused where it
   used to be kept when a slot was free. The first is the one this protects.

3. **The view-less queue keeps the lowest revisions.** When it is full and the
   arriving control is lower than the highest held, the arriving control takes
   the highest one's place. A control higher than all held is refused, as before.
   The queue then holds the four lowest revisions it was sent, in whatever order
   they came, and `join_group` applies them from the bottom. The control it
   drops was consumed and acknowledged, so it is lost like any control past the
   window, and the authority, which records relay acceptance and not receipt,
   does not know (0142). The reach is one less than with a view: four slots and
   no next-revision shortcut mean that after `join_group` at revision `v` a
   member reaches `v + 4` from what it was sent, where a member with a view
   reaches `v + 5`. A queue that has a view is unchanged.

4. **A held removal is a window, stated.** The holder's view is the only state
   the roster rules define, and it lists the removed member until the predecessor
   arrives and the removal is applied. The removed member's pairwise session
   decrypts what the holder sends; its own group layer, which applied the
   removal, refuses the message (`NotActive`), so nothing is delivered to the
   application, but the ciphertext was made for it. The window is the time
   between the removal's arrival and its predecessor's. It is no wider than
   before 0142, when the holder refused the removal and stayed at revision 1
   for good. A test pins the behaviour.

## Considered

- **Prefer identities the roster or the invitation book knows** (the first
  design offered). The member the next roster admits is unknown to both on every
  member but the authority. Rejected as unable to help.
- **Evict the oldest with a bounded share per sender.** A context that was
  answered `Deferred` would later disappear without an outcome, the newest
  sender wins, so a stranger that sends last wins, and the eviction is a second
  silent-loss path. Rejected.
- **More unlisted slots.** The attacker needs proportionally more identities and
  a legitimate burst is kept longer; the receiver state bound and the codec limit
  change, and the limit stays. Not done.
- **Prefer senders named by a held roster control.** Correct when it applies,
  and it needs a new parameter through the group crate's `receive`; it does not
  apply when the next revision is the one missing, which is the case reproduced.
  Left for a decision on catch-up (0142).
- **A fifth slot for the view-less queue, or reserving the lowest.** A fifth slot
  changes the `TCGQ` bound, its decoder and the 12 KB of 0142 to move the limit
  by one; keeping the lowest revisions needs none of that.
- **Stating the view-less limit only.** It leaves a member stranded for want of
  one slot, where it is stranded at worst four revisions later with the change.
- **Excluding members a held control removes from `send_group`.** The holder
  cannot validate the removal against its own chain: the missing predecessor may
  re-add the member, or the held control may be a fork. Acting on it would
  trade the confidentiality window for a wrong exclusion. Not done.

## Limits this record leaves, exactly

- Two registered identities that know the group ID and a member's route still
  take both open slots, and the first message of a just-admitted member is lost.
- A just-admitted member's second early message before the roster arrives is
  refused.
- A view-less coordinator reaches `v + 4`, and the control its queue drops is
  lost unannounced.
- A holder of a removal it cannot apply sends to the removed member until the
  predecessor arrives.

## The five questions

1. **Does this keep the trusted core small?** Yes. The group crate's receiver is
   product policy; the core is untouched.
2. **Is the behaviour owned by a written specification?** By this record and the
   ones it amends. The Lean model has no receiver and no queue (0137).
3. **Can the security claim be reproduced?** `tacenta-group` `tests/limits.rs`
   (`one_unlisted_identity_holds_one_of_the_two_open_deferred_slots`,
   `the_receiver_state_refuses_two_deferred_contexts_of_one_unlisted_identity`);
   `group_client::tests::deferral_slots` (one stranger with four contexts before
   the admitted member's, and the two-identity limit); `held_roster_controls`
   (four arrival orders of five controls ending at the same revision after a
   restart); `roster_fanout` (the held removal).
4. **Does it preserve wire compatibility with a named profile?** Yes. No wire
   bytes change. The receiver state layout is unchanged and accepts a subset of
   what 0142 accepted; no state written by `GroupClient` exists outside the
   branch that introduced it.
5. **Is this protocol functionality, or product coupling trying to enter the
   core?** Product coordination.

## Why

A guarantee that a single peer can defeat is not one. The rule that closes the
single-peer case costs a legitimate burst its second message, which is the
smaller loss, and the record says which case remains open and why nothing local
can close it.

## What would reopen this

A catch-up or receipt protocol (a member could ask the authority for the roster
it is missing), a way for members to learn an invitee before the roster (an
invitation announced to the group), or a measured group in which early bursts are
common.
