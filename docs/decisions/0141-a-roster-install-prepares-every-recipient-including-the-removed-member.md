# 0141 — a roster install prepares every recipient, including the member it removes

> Amends 0124, 0125 and 0131. Amended by 0145 (point 2 finds the replaced roster in a
> checkpoint, not in the transcript).

`GroupClient::install_roster` installs a successor roster locally and sends it
to a list of recipients (0124). The install and the first recipient's exact
ciphertext are one commit; every later recipient is prepared against the roster
that is now installed. That made the outcome depend on the order of the list.

## Decision

1. **Who may receive an install is decided once, before anything changes.** A
   recipient of a successor may be a member of the roster being replaced, a
   member of the successor, or an invitee whose invitation is unexpired (the sets
   0124 and 0125 already defined). `install_roster` checks every listed
   recipient against those sets up front and refuses the whole call with
   `GroupError::Policy` if any is not covered, before it installs or prepares
   anything. A call with no recipients for a successor that is not installed yet
   is refused the same way: the install is fused with the first recipient's
   commit, so with none there is nothing to commit, and the previous
   `Ok(Duplicate)` reported an install that had not happened.

2. **The member an install removes is a recipient of it, wherever it is
   listed.** Once the successor is installed the recipient check for the
   remaining recipients also admits the members of the roster the installed
   successor replaced. That roster is found by digest, not remembered in memory:
   the successor names its predecessor's digest, and the predecessor's preimage
   is kept in a checkpoint record (`TCGS`, 0145) that the commit installing the
   successor writes. It therefore survives a restart. It is the immediate
   predecessor only. (As first written this point read the preimage from the
   roster records of the control transcript, `TCGC`, which 64 later control
   records evict; a peer that is not in the group could cause them, and the first
   call was not refused up front as this point said. 0145 replaces the lookup.)

3. **A recipient that already holds this control is served from it.** A retry
   of `install_roster` for an installed successor finds an existing handoff:
   a delivered one is reported `delivered` (it was reported `pending` before,
   because a fresh preparation conflicted with the stored ciphertext), a
   prepared or handed-off one is dispatched with its stored bytes as before.

4. **`Install` says what a retry needs.** `delivered`: the relay accepted it.
   `pending`: a control is committed and not accepted; `dispatch_pending_controls`
   sends it when it is still waiting for the relay. A recipient whose handoff is
   final also stays here and nothing sends it again: its third and final attempt
   was not confirmed (0134;
   `r091_a_control_whose_attempts_are_used_up_is_pending_not_unprepared` covers this), or the
   control was cancelled. The cancelled arm exists in the code and no test reaches
   it through `install_roster`: the revocation of an invitation is what cancels a
   handoff, and it also ends that recipient's entitlement to be told. `unprepared` (new): nothing was
   committed for this recipient (a transient failure while preparing, or a full
   control outbox); call `install_roster` again with the same successor. Before
   this record a recipient in `pending` could be one for whom nothing was
   prepared, and the documentation sent the caller to a call that could not
   help.

5. **Three neighbouring calls refuse what cannot work, before any pairwise
   operation.** `send_group` refuses a route whose device is not the
   recipient's device (the message was relay-accepted and unusable: the wrong
   device received a ciphertext for another). `create_group` and `join_group`
   refuse a group id other than the one the store's roster records belong to (a
   second id on a used store wedged the coordinator: every later install and
   send answered `Policy`). `invite` refuses a closed group (the invitation and
   its bootstrap were recorded and sent, and the invitee could only refuse it).

## The failure this prevents

Reproduced on the integrated branch: `install_roster(r2, [carol, bob])` where
`r2` removes Bob delivered Carol's copy and left Bob at revision 1, because Bob
was prepared after the install and was no longer in the installed roster; a
retry failed the same way. Removing Bob and Carol with recipients `[bob,
carol]` told only Bob. The lane tests listed the removed member first, which is
why they passed; the order of members in a roster is the canonical byte order
(0136), unrelated to who is removed, so which order an application produces is
luck. Members that have applied the roster stop encrypting to a removed
member, but a member that has not (it never received the control, or holds it
for a missing predecessor, 0146) still does; the removed member kept sending
revision-1 traffic that was refused and never learned it was out.

## Considered

- **List the removed members first inside `install_roster`.** Rejected: with
  more than one removed member only the first fits in the fused commit, so the
  bug moves to the second.
- **Remember the departed members in memory.** Rejected: lost at restart, which
  is when a partly delivered install is retried.
- **Persist a notification list beside the control outbox.** Rejected: a new
  state layout for information the roster records already hold.
- **Let the caller name any recipient.** Rejected: a mistake would disclose a
  roster to a stranger, and the check is what 0124 relies on.

## Limits this record leaves, exactly

- Only the immediate predecessor's members are covered (0145). A member removed
  two installs ago cannot be sent a notice by this call.
- A removed member that never receives the control (relay loss, an unreachable
  device) is not followed up: there is no catch-up or acknowledgement protocol
  (0142 states the limit for members).
- The check is the authority's. It does not authenticate the recipient beyond
  the pairwise session the ciphertext is encrypted to.

## The five questions

1. **Does this keep the trusted core small?** Yes. Product coordination only.
2. **Is the behaviour owned by a written specification?** By this record and the
   ones it amends; the roster record layout does not change.
3. **Can the security claim be reproduced?** `group_client::tests::roster_fanout`
   installs a removal with the removed member listed last, first and in the
   middle, removes two members at once, retries after a failure and after a
   restart, and checks the refusals of point 5, all through `GroupClient` with
   the provider's outcome.
4. **Does it preserve wire compatibility with a named profile?** Yes. No byte
   changes.
5. **Is this protocol functionality, or product coupling trying to enter the
   core?** Product coordination.

## Why

A membership operation whose result depends on list order is a defect the caller
cannot see until a member is left behind. The information needed to notify the
removed member was already durable; the check only had to read it.

## What would reopen this

A delivery receipt or catch-up protocol (which could make the immediate
predecessor insufficient), a multi-device profile, or a notification that must
reach members removed more than one revision ago.
