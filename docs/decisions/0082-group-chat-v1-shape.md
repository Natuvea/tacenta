# 0082 — group chat v1: the recommended shape

## What this is

Group chat plus the sealed-sender direction and member-enforced
moderation (0081) raise a handful of load-bearing design choices. This records the
**recommended v1 shape** for each — the direction of record — with the trade that
justified it and the residual it carries. It is not built; the crypto choices in
particular are ratified as the *default plan* and revisited when group chat is actually
scheduled, not treated as immutable.

**The v1 shape in one line:** sender-key groups (reusing the proved post-quantum
ratchet for key distribution) + admin-signed membership epochs + a blind
hash-chained sequencer + sealed sender + a toggleable franking hook — all
tested-first, with the removal invariant proved early. MLS is the north star we
leave room for, not the thing we build first.

## The choices

Each lists the options considered, the pick, why, and what it costs.

### 1. Group cipher foundation
- *Options:* pairwise fan-out (N 1:1 messages) · **sender-key + signed roster** · MLS/TreeKEM (RFC 9420).
- **Pick: sender-key + signed roster.** It reuses tacenta's *already-proved
  post-quantum* pairwise ratchet for the one hard part — distributing the sender
  key — so we do not reinvent and re-prove PQ group crypto. It is the group-chat plan.
- *Why not MLS now:* best security and removal-as-a-commit, but standard
  ciphersuites are **not post-quantum** (tacenta is; PQ-MLS is draft-stage) and the
  clean-room proof burden is enormous. Kept as the north star; keep the roster layer
  clean enough to swap later. Pairwise fan-out stays the right tool for tiny groups
  and the demo, not a real cipher.
- *Residual:* sender-key FS is coarser (per-sender symmetric chain); removal needs
  an explicit re-key (see 0081).

### 2. Membership authority (who may change the roster)
- *Options:* **admin-signed epochs** · any-member commit (MLS-style) · server-serialized.
- **Pick: admin-signed epochs, with authority stored as a policy field in the
  signed state** (not hardcoded), so multi-admin / any-member can come later without
  a redesign. Maps 1:1 to the owner/admin/member model in 0081.
- *Why not server-serialized:* it would make the server learn roster and roles —
  against the blind-server principle.
- *Residual:* a compromised admin key is group takeover — mitigated by identity-key
  rotation and by every admin action living in the tamper-evident transcript, so a
  rogue admin is at least auditable.

### 3. Ordering / consistency of group state
- *Options:* **blind sequencer** (relay totally-orders opaque, sender-anonymous
  commit blobs, each hash-chained to the prior epoch) · fully decentralized (gossip
  + consensus).
- **Pick: blind sequencer + hash-chained epochs.** Members detect any
  reorder/drop/fork, so the ordering is *verified*, not trusted; the server orders
  opaque blobs without learning sender or content. Full decentralization is a
  research project, not v1.
- *Residual:* the server learns *that* a group had an event at time T and its epoch
  count — a small, named metadata surface (activity timing, not who/what).

### 4. Sealed sender
- *Options:* **go blind** (sealed sender + delivery tokens) · keep sender known.
- **Pick: go blind, sequenced sealed sender before group moderation.**
  It is the product's design principle, and a sender-known moderation path
  would be built to be ripped out. The abuse-tooling loss is bought back with
  membership gating + franking (0081).
- *Pragmatic alternative, taken consciously if needed:* ship 1:1 sender-known as a
  v0 to get a product moving — safe only because the moderation layer is already
  designed sealed-sender-ready.
- *Residual:* no server-side per-sender rate-limiting; anonymous sending needs
  delivery tokens.

### 5. Operator abuse reporting
- *Options:* **message franking (hook now, flow toggleable)** · none (client-side
  blocking only).
- **Pick: build the franking hook now; make the reporting flow a per-deployment
  toggle.** A high-privacy self-host runs without it; a commercial tenant with ToS
  obligations turns it on — the same posture-choice pattern as the relay cap and
  registration policy. Deciding the hook now avoids a later wire change.
- *Residual:* on report, the operator learns a specific reported message's content
  and that it transited — never sender-at-send-time or anything unreported.

### 6. Verification depth for the group layer
- *Options:* proved (Lean/Aeneas T3) up front · **tested-first, proved
  incrementally**.
- **Pick: tested-first, proved incrementally — exactly how the 1:1 core was built —
  proving the *removal invariant* first** (a removed member cannot derive
  post-removal keys), since that is the security-load-bearing property.
- *Residual:* a temporary "group layer is tested, not yet proved" caveat, which
  **is stated in `docs/claims.md` from the day the layer lands**.

### 7. Developer try-it experience
- **Pick: build both** `tacenta-group-demo` (scripted; doubles as the integration
  test) and the interactive `echo-room`. Low cost, and
  the scripted one pays for itself as the test.

## Status

Direction of record for group chat, sequenced after sealed sender. Choices 4–7 are stable
postures we can commit to now; choices 1–3 (the crypto foundation, membership
authority, and ordering) are the recommended defaults and should be **re-ratified
at the moment group chat is scheduled**, against whatever the group security and scale
requirements turn out to be then. Moderation specifics live in 0081; the clean-room
cipher rule in 0075.
