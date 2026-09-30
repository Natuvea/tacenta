# Group wire and record formats: inventory

This page lists every byte format that the bounded group-chat experiment
(`tacenta-group` and the group modules of `tacenta-client`) defines, and says
for each where it is written and read, what bounds it carries, whether a
decision record describes it and whether any specification text does. It is
an inventory of what the code at the revision below does, not a specification;
the specification of the first slice is
[`spec/group-wire-formats.md`](../spec/group-wire-formats.md), and decision
[0149](decisions/0149-group-wire-format-specification-first-slice.md) records
why that slice was chosen.

Revision inventoried: `2062899` (main after the bounded group-chat profile was
merged). Line numbers and the "Spec text" column are for that revision; the
seven formats of the first slice have been specified since (see the page above),
and the local records below are still not. All lengths are bytes. "Domain" is
the fixed ASCII string a value starts with; "tag" is a four-byte ASCII record
tag used inside the operation snapshot.

## Summary

- **Eleven domain strings, fourteen record tags, one snapshot framing.**
  Eleven `Tacenta Group ...` domain strings (ten end in `v1`, one in `v2`),
  fourteen `TCG?` record tags, and the `TCOP` snapshot framing.
- **Three of the eleven domain strings appear in a decision record** (roster,
  application context, logical send). Eight appear in no decision record,
  specification text, contract or vector: the group payload, the three
  invitation records, and the invitation-book, receiver-state, roster-view and
  control-outbox states.
- **The five group payload tags (1 to 5) are documented nowhere.** Decision
  0118 says "one explicit type byte" and two variants; 0125 and 0126 add three
  more without giving their numbers.
- **The only vectors that touch the group profile are `group-v1.json`,** which
  the Lean model generates. They are policy traces: they carry no bytes, so no
  byte layout in this page is covered by a committed vector at this revision.
- **Field widths are not uniform.** Most formats frame variable and fixed-size
  fields with a 4-byte length; the invitation bootstrap frames the target member
  with a 2-byte length and carries the group ID, invitation ID and digests
  with no length at all; the invitation-book state also uses 2-byte lengths.
  A reader cannot infer one format's framing from another's.
- **Input-size bounds are not uniform either.** The roster (4,096), application
  context (2,048), group payload (8,192) and receiver state (262,144) decoders
  refuse an oversized input before parsing. The bootstrap, acceptance,
  revocation, logical-intent, invitation-book, roster-view, control-outbox,
  held-roster and snapshot decoders have no bound of their own; their
  allocation is bounded by the length of the input they are handed.

## Classes

- **P, peer-exchanged.** Bytes inside the plaintext of a pairwise-authenticated
  message that a `group`-class relay envelope carries between two clients. A
  second implementation must produce and accept them to interoperate.
- **B, recovery boundary.** Bytes a client writes to its own durable store and
  decodes again on restart. No peer reads them, but a decoder that accepts a
  wrong value there is a persistence-trust decision. The logical-send intent is
  the one such record that `tacenta-group` exposes as public API.
- **L, local record.** Bytes a client's operation store keeps and only that
  client's code reads. They are product-owned and may change with the product.

## Peer-exchanged formats (P)

All of these are the plaintext of a pairwise message. The relay envelope that
carries them is specified in `spec/Tacenta/Wire.lean` (`kind = group`); the
pairwise layer is tacenta-core's.

| Format | Domain string (bytes) | Written | Read | Bounds in code | Decision record | Spec text at `2062899` |
| --- | --- | --- | --- | --- | --- | --- |
| Group payload (tags 1 to 5) | `Tacenta Group Payload v1` (24) | `payload.rs:29` | `payload.rs:53` | whole payload 8,192 (`payload.rs:14`); tag byte 1 to 5 (`payload.rs:9-13`); length must equal the remainder | 0118 (envelope, two variants), 0121 (router), 0125 and 0126 (three more variants). No record gives the tag numbers or the byte layout. | none |
| Roster (tag 2) | `Tacenta Group Roster v1` (23) | `lib.rs:227` | `lib.rs:245` | 4,096 whole (`lib.rs:45`); 8 members (`lib.rs:37`); identity 256 (`lib.rs:41`); device 64 (`lib.rs:43`); group ID 16; digest 32; policy version 1; revision `u64::MAX` reserved | 0092 (layout; amended by 0136 for order), 0104 (limits) | none |
| Application context (tag 1) | `Tacenta Group Application v1` (28) | `lib.rs:372` | `lib.rs:386` | 2,048 whole (`lib.rs:47`); payload 1,024 (`lib.rs:39`); identity 256; device 64; digest 32; revision `u64::MAX` reserved | 0094 (layout), 0104 (limits) | none |
| Invitation bootstrap (tag 3) | `Tacenta Group Invitation Bootstrap v1` (37) | `invitation.rs:157` | `invitation.rs:173` | none of its own; embedded roster 4,096; target identity 256 and device 64 (checked after the roster is read); policy version 1; source revision `u64::MAX` reserved | 0125 (fields, not bytes); 0093 says it "does not specify the invitation wire bytes" | none |
| Invitation acceptance (tag 4) | `Tacenta Group Invitation Acceptance v1` (38) | `invitation.rs:231` | `invitation.rs:246` | fixed length 110; source revision `u64::MAX` reserved | 0125 (fields, not bytes) | none |
| Invitation revocation (tag 5) | `Tacenta Group Invitation Revocation v1` (38) | `invitation.rs:294` | `invitation.rs:309` | fixed length 110; source revision `u64::MAX` reserved | 0126 (fields, not bytes) | none |

The core commitments that later revisions and receivers compare these bytes
with are owned by tacenta-core (`groups.rs`, `roster_commitment` and
`payload_commitment`, SHA-256 over a fixed label and the bytes). Decision 0092
quotes the roster label; no document in this repository quotes the payload
label.

## Recovery-boundary format (B)

| Format | Domain string (bytes) | Written | Read | Bounds in code | Decision record | Spec text at `2062899` |
| --- | --- | --- | --- | --- | --- | --- |
| Logical-send intent (the body of `TCGI`) | `Tacenta Group Logical Send v1` (29) | `send.rs:494` | `send.rs:526` | none of its own; payload 1,024 (`lib.rs:39`); recipients 1 to 8; identity 256; device 64 | 0105 (layout), 0111 (recovery codec), 0136 (recipient order) | none |

## Local records (L)

These are read only by the client that wrote them. None is covered by a
specification page or a byte vector.

### Group state values

| Format | Domain string (bytes) | Written | Read | Bounds in code | Decision record |
| --- | --- | --- | --- | --- | --- |
| Receiver state (the snapshot's `application_state`) | `Tacenta Group Receiver State v1` (31) | `receive.rs:209` | `receive.rs:256` | 262,144 whole (`receive.rs:16`); accepted entries `8 * 64`; deferred 4 (`receive.rs:10`), of which 2 unlisted (`receive.rs:14`) | 0113 (retention), 0114 (codec), 0139 (terminal state), 0142, 0146 |
| Roster-view state (wrapped in `TCGV`) | `Tacenta Group Roster View State v1` (34) | `roster_view.rs:108` | `roster_view.rs:123` | none of its own; embedded roster 4,096 | 0115 |
| Invitation-book state (wrapped in `TCGB`) | `Tacenta Group Invitation Book State v1` (38) | `invitation.rs:415` | `invitation.rs:456` | 32 records (`invitation.rs:11`); 2-byte lengths | 0120 |
| Control-outbox state (wrapped in `TCGO`) | `Tacenta Group Control Outbox State v2` (37) | `group_control_outbox.rs:249` | `group_control_outbox.rs:290` | 8 live and 16 terminal handoffs, 3 attempts (`group_control_outbox.rs:13-16`) | 0119, 0124, 0133 |

Ten of the eleven domain strings end in `v1`. The control-outbox state ends in
`v2`, and no record says what `v1` of it was.

### Operation snapshot

| Format | Tag | Written | Read | Bounds in code | Decision record |
| --- | --- | --- | --- | --- | --- |
| Operation snapshot framing | `TCOP` then a version byte (1 or 2) | `operation_store.rs:60` | `operation_store.rs:95` | none of its own; the collections are bounded by the coordinator (`group_operations.rs:35-42`): `group_controls` 64, `inbox` 64, `dedup` 512, terminal sends 16 | 0091, 0132, 0133 |

The snapshot holds the provider state, the receiver state, and four record
collections (`outbox`, `inbox`, `dedup`, `group_controls`) plus a delivery
cursor. Version 1 has no `group_controls` collection and a decoder rewrites it
as version 2.

### `TCG?` transcript records

Each record is a four-byte tag followed by its body. The `outbox`, `inbox` and
`group_controls` collections hold them.

| Tag | Collection | Written | Read | Contents | Decision record |
| --- | --- | --- | --- | --- | --- |
| `TCGI` | `outbox` | `group_operations.rs:2467` | `send.rs:322`, `group_operations.rs:2278` | length-prefixed logical-send intent | 0105, 0111 |
| `TCGP` | `outbox` | `group_operations.rs:2328` | `send.rs:350` | length-prefixed application context, 32-byte commitment, length-prefixed ciphertext | 0108, 0110, 0112 |
| `TCGH` | `outbox` | `group_operations.rs:2476` | `send.rs:380` | as `TCGP`, then attempts and a disposition byte | 0106, 0112 |
| `TCGA` | `outbox` | `group_operations.rs:2503` | `send.rs:350` | as `TCGP` | 0109, 0112 |
| `TCGR` | `inbox` | `group_operations.rs:2522` | `group_operations.rs:2645` (layout only) | effect code, length-prefixed context (empty once delivered), commitment, disposition | 0099, 0133, 0144 |
| `TCGM` | `inbox` | `group_operations.rs:2583` | not read | effect code, plaintext length, payload commitment (41 bytes) | 0107, 0133 |
| `TCGC` | `group_controls` | `group_operations.rs:2721` | not read | length-prefixed roster preimage, commitment, disposition | 0141, 0145 |
| `TCGE` | `group_controls` | `group_operations.rs:2763` | compared as a literal in one test (`group_operations.rs:4644`) | effect code (5 bytes) | none |
| `TCGV` | `group_controls` | `group_operations.rs:2772` | `group_operations.rs:2835` | length-prefixed roster-view state | 0122, 0133 |
| `TCGB` | `group_controls` | `group_operations.rs:2781` | `group_operations.rs:2790` | length-prefixed invitation-book state | 0122, 0133 |
| `TCGO` | `group_controls` | `group_operations.rs:2808` | `group_operations.rs:2817` | length-prefixed control-outbox state | 0122, 0133 |
| `TCGX` | `group_controls` | `group_operations.rs:2456` | `group_operations.rs:2416` | group ID, revision (24 bytes with the tag) | 0122, 0133 |
| `TCGQ` | `group_controls` | `group_deferred_rosters.rs:115` | `group_deferred_rosters.rs:133` | group ID, count byte, length-prefixed roster preimages; at most 4 (`group_deferred_rosters.rs:15`) | 0133, 0142, 0146 |
| `TCGS` | `group_controls` | `group_operations.rs:2443` | `group_operations.rs:240` | group ID, length-prefixed roster preimage | 0141, 0145 |

## Notes

1. **Checkpoint records replace their predecessors.** Six tags (`TCGV`,
   `TCGB`, `TCGO`, `TCGX`, `TCGQ`, `TCGS`) name checkpoints: a new one replaces
   the previous of its kind (per group for `TCGX`, `TCGQ` and `TCGS`), and the
   64-record bound never evicts the latest of each kind
   (`group_operations.rs:45`, `2350-2413`).
2. **Two records are evidence only.** `TCGM` and `TCGC` are written and never
   parsed again; `TCGR` is parsed for its layout and event ID only.
3. **A tag with the prefix `TCG` that no decoder knows is an error** where the
   transcript is replayed (`send.rs:311`, `group_operations.rs:2293`).
4. **Big-endian everywhere.** No format in the profile uses another byte order.
5. **Where the layout is in an ADR, the ADR is the only description.** Decision
   0092 describes the roster's authority as `lp(authority_binding)`, and the
   code writes two length-prefixed fields for it. Decision 0105 does the same
   for the sender. This was open point 1 of the specification; on 2026-09-30 the
   code's form was decided to be the specified one, and both decisions were
   amended.
6. **The Lean model has no bytes.** `spec/Tacenta/Group.lean` treats members as
   two numbers and commitments as numbers (decision 0137, item 11), so none of
   these layouts can be generated from it.
7. **Some encoders checked less than their decoders at this revision.** The
   invitation bootstrap (no target size check, a reserved revision or wrong policy
   reported as `conflict`), the logical-send intent (no size, count or payload
   check of its own), the invitation-book state (no check of a record's fields)
   and the receiver state (no check of the local member) wrote bytes that the
   same crate then refused. They make their decoders' checks since 2026-09-30
   (decision 0149, open point 4).

## What the first slice covers

The group payload, roster, application context, invitation bootstrap,
acceptance and revocation, and the logical-send intent: seven formats. The
local records above are outside it, for the reasons in decision 0149.
