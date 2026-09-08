# 0081 — moderation is member-enforced, the server stays blind

## The problem

Group chat brings moderation with it. The obvious design is server-managed: a
`group_members` table with roles (owner/admin/member), server-enforced
authorization ("an admin may act only on members, never the owner or another
admin"), ban tombstones that block rejoin, timed mutes, and an append-only
`moderation_events` audit.

**It cannot be used here, because it inverts this product's core principle.**
Server-managed moderation works *only because the server owns membership and
knows who did what*. Tacenta goes the other way: **sealed sender** (sequenced
before groups) makes the relay blind to *who sent* a message, on top of a relay
that is already blind to content and is deliberately thin (decision 0017). The
product's design principle is a server that knows as little as possible — not
content, not the sender, and ideally not the group's membership or roles.
Server-side moderation is incompatible with that server.

## Decision

**Moderation is enforced by the group's members cryptographically, not by the
server.** The server never becomes a policy engine; it stays a blind store-and-
forward of sealed envelopes.

- **Membership is an admin-signed, member-verified epoch.** An add or remove is a
  *signed commit*, not a server row. Every member's client verifies the actor was
  authorized by the group's policy and applies it. A malicious or compromised
  server can neither forge a commit (signature) nor silently drop one forever
  (members see the gap in the transcript).
- **Removal is a re-key, enforced by math.** Removing a member rotates the group's
  keys to the new roster; the removed member can no longer derive keys (cannot read
  new messages) and their outbound is dropped by members who reject a sender not in
  the current roster (cannot send). The server does nothing and learns nothing.
- **Roles and policy live in the signed group state**, not on the server. The
  owner/admin/member matrix and the mute/ban/kick semantics are the *model and
  UX*, expressed as signed group policy rather than server rows.
- **The audit is the signed commit transcript** — tamper-evident and
  reconstructable by any member — in place of a server-held `moderation_events`
  table, and stronger for it: a server can rewrite a table row, but it cannot forge
  a signature.

## The residuals, stated plainly

A blind server genuinely gives up tools a server-managed design has. These are
accepted, not hidden:

1. **No server-side per-sender rate-limiting.** The server cannot throttle a
   specific abuser it cannot see. Abuse control moves to *membership* (kick/ban →
   re-key) and *client-side blocking*; non-members are gated by not holding the
   group send key. The recipient-keyed relay byte-budgets and the registration
   limits (0079, 0080) are unaffected (they never keyed on the sender).
2. **Anonymous sending must still be authorized.** Sealed sender means the relay
   cannot authenticate the sender, so it needs **delivery tokens / sender
   certificates**: the server confirms a sender is *allowed* to send to a
   recipient without learning *who they are*.
3. **Operator abuse *reporting* requires message franking.** The one server-assist
   compatible with sealed sender: the server blindly stamps a commitment at send
   time, so a recipient can later report a specific message and the operator can
   verify it genuinely transited — without the server reading content or knowing
   the sender at send time. If a deployment wants any "report this message"
   recourse, franking is designed in from the start; without it, reporting is
   client-side only, with no cryptographic proof.
4. **This is real protocol design, not app logic.** Member-enforced membership with
   re-key on removal is the problem MLS (RFC 9420) solves; it sits *above* the group
   cipher (sender keys) and must be built clean-room in tacenta-core. It is
   substantially harder than a server table — that difficulty is the price of
   the blind server, paid on purpose.

## Status

Direction of record for group-chat moderation. Sequenced after sealed sender:
the server must be blind to senders *before* group moderation is
built on that blindness. Not built; folded into sealed-sender/group-chat scoping.
The surrounding group-design choices this sits inside — the cipher, membership
authority, ordering, franking, and verification depth — are recorded in **0082**.
