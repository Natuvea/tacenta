# 0137 — bounded group invitation admission rules and revision numbering

> Clarifies 0093. Aligns `spec/Tacenta/Group.lean` with the code.

## Decision

**Revision numbering.** An invitation does not advance the roster revision. It
records the authority's current revision as its source revision, together with
the source roster digest, and travels to the target as a bootstrap control
(decision 0125). Only a roster successor advances the revision: an admission,
a removal or a closure. Adding a member therefore costs exactly one revision,
the admission. A group at revision 0 that invites one person and admits them
is at revision 1, and a second invitee admitted afterwards is at revision 2.
The Lean model previously recorded a successor for the invitation as well
(invite to revision 1, admit to revision 2); it is changed to the numbering
above and its traces read invite at revision 0, admit at revision 1.

**Creation.** `InvitationBook::create` refuses an invitation whose target
identity already appears in the active roster (which covers the exact member
and a second device of an existing identity) with `Conflict`, and refuses a new
invitation while the active roster already holds eight members with
`TooManyMembers`. An exact retry of an existing record returns that record
before the capacity check, so a retry never fails because the roster has since
filled. The pending invitations themselves do not count toward the eight.

**Admission.** `InvitationBook::admit` refuses a revision that is not strictly
greater than the invitation's source revision with `StaleSource`, because an
admission is a successor of the source roster or of a later one. A retry of an
admitted invitation at the same revision returns the record; a different
revision is a `Conflict`. The book has no roster to check, so the eight-member
cap and the one-device rule at admission are enforced where the successor
roster is built: `Roster::new` refuses a ninth member (`TooManyMembers`) and a
second device of an identity (`NonCanonical`).

**Acceptance is idempotent.** A repeated acceptance of an accepted-pending or
admitted invitation returns the committed record and changes nothing. The
acceptance control is retried up to three times and a crash may resend it, so
the second delivery must be safe. The Lean model's `accept?` refused a
repeat; it now returns the unchanged state for a repeat while the invitation
is unexpired or admitted.

**Model and code are tied by a vector.** `lake exe vectors group` prints a
trace of invite, accept, admit, revoke and refusal steps from the Lean model,
committed as `contracts/vectors/group-v1.json`; CI regenerates it with the
other four. `crates/tacenta-group/tests/model_vectors.rs` replays every step
against the Rust types and compares refusals and revision numbers.

## Considered

- Make the code follow the model: an invitation consumes a revision. That
  spends a revision, and a control fan-out to every member, on an invitation
  that may be revoked or expire; it changes the live traces and the wire bytes
  the client tests already fix (admission at revision 1).
- Keep two numberings and document the difference. That leaves a model whose
  traces mean something other than the code.
- Make acceptance strict, as the model had it. A resent acceptance would then
  fail at the authority.

## Why

The revision space is bounded (`u64::MAX` is reserved) and every revision is a
control message that every member must accept in order. Revisions should count
changes to who is in the group. An invitation is authority-side state plus a
point-to-point bootstrap, so the model follows the code and the start pack
("B is admitted at r1 ... C observes r1 pending, then is admitted at r2").
Retry safety decides the acceptance question: an operation that a crash can
repeat must not turn its own repeat into an error.

## What would reopen this

A profile in which an invitation is itself a group-visible event (a delegated
authority, or a group that shows pending invitations to every member) needs a
revision for it. A multi-device profile changes the second-device rule.
