# Bounded group-chat wire formats, version 1 (first slice)

Status: **experimental profile, unreleased.** This page states the bytes of the
formats that the bounded group-chat experiment exchanges between peers (and one
that it recovers from its own store), so that an implementation can be written
from this text. It describes what the code at revision `2062899` does, except
that the encoders of the invitation bootstrap and of the logical-send intent now
refuse what their decoders refuse (open point 4, below). Every place where that
behaviour had no stated reason or disagreed with a decision record is in
[Open points](#12-open-points): four were decided on 2026-09-30 and four remain
open. It is not a compatibility promise: nothing in the group profile has been
released, and a human decision on an open point can change a layout (which would
then change its domain string from `v1`). Decision
[0149](../docs/decisions/0149-group-wire-format-specification-first-slice.md)
records why this slice was chosen and what it leaves out.

The formats specified here are:

| Section | Format | Domain string |
| --- | --- | --- |
| 5 | Roster preimage | `Tacenta Group Roster v1` |
| 6 | Application context | `Tacenta Group Application v1` |
| 7 | Invitation bootstrap | `Tacenta Group Invitation Bootstrap v1` |
| 8 | Invitation acceptance | `Tacenta Group Invitation Acceptance v1` |
| 9 | Invitation revocation | `Tacenta Group Invitation Revocation v1` |
| 10 | Group payload (tags 1 to 5) | `Tacenta Group Payload v1` |
| 11 | Logical-send intent | `Tacenta Group Logical Send v1` |

Not specified here: the receiver, roster-view, invitation-book and
control-outbox states, the `TCG?` transcript records and the `TCOP` snapshot
framing. They are local records, read only by the client that wrote them (see
the inventory in [`docs/group-wire-format-inventory.md`](../docs/group-wire-format-inventory.md)).
The pairwise encryption, the relay envelope that carries a `group`-class message
(`Wire.lean`, kind `group`) and the semantics of membership, invitations and
delivery are also outside this page. Lean is not involved: `Group.lean` models
policy transitions and has no bytes (decision 0137, item 11).

The words MUST, MUST NOT and MAY are used as in RFC 2119.

## 1. Notation

- A **byte string** is a sequence of octets. Everything is byte-oriented and
  **big-endian**.
- `u16`, `u32`, `u64`: an unsigned integer in 2, 4 or 8 bytes, most significant
  byte first.
- `raw(n)`: exactly `n` bytes with no length prefix.
- `lp32(x)`: `u32(len(x)) || x`. `lp16(x)`: `u16(len(x)) || x`, defined only
  for `len(x) < 65536`.
- `"text"`: the ASCII bytes of the text, with no terminator and no length
  prefix. A **domain string** is such a literal at the start of a value; it is
  compared byte for byte.
- `0xNN`: the single byte with that hexadecimal value (`0xFF` is one byte, 255).
- `a || b`: concatenation.
- A **member** is a pair of byte strings, `identity` and `device`. Its **long
  form** is `lp32(identity) || lp32(device)`. Its **short form** is
  `lp16(identity) || lp16(device)`. Formats say which form they use.
- **Member order.** Members compare as the pair `(identity, device)`: identity
  bytes first, as unsigned byte strings in lexicographic order (a proper prefix
  sorts before every extension of it), and device bytes, compared the same way,
  only when the identity bytes are equal. The order is never taken over the concatenation
  `identity || device` (decision 0136).
- **Reading.** A decoder reads its input from the front. `read(n)` returns the
  next `n` bytes; if fewer than `n` remain, decoding stops with the refusal
  `malformed`. `read_lp32()` reads a `u32` `n` and then `read(n)`; `read_lp16()`
  reads a `u16` `n` and then `read(n)`. `read_member()` is two consecutive
  `read_lp32()` calls (long form) followed by the size check of section 2;
  `read_member16()` is two `read_lp16()` calls (short form) and performs **no**
  size check at that point.
- **Revision.** A revision is a `u64`. The value `2^64 - 1` is **reserved** and
  is never a valid revision anywhere on this page. The largest usable revision
  is `2^64 - 2`.

## 2. Constants

| Name | Value | Meaning |
| --- | --- | --- |
| group ID length | 16 | a group ID is `raw(16)` opaque bytes |
| invitation ID length | 16 | an invitation ID is `raw(16)` opaque bytes |
| digest length | 32 | a roster or context digest is 32 bytes |
| policy version | 1 | the only policy version; carried as a `u32` |
| maximum members | 8 | members in a roster, recipients in an intent |
| maximum identity length | 256 | bytes of one member's `identity` |
| maximum device length | 64 | bytes of one member's `device` |
| maximum application payload | 1,024 | bytes of the `payload` in a context or an intent |
| maximum roster length | 4,096 | bytes of a roster preimage, as an input |
| maximum context length | 2,048 | bytes of an application context, as an input |
| maximum group payload length | 8,192 | bytes of a group payload, as an input |
| reserved revision | `2^64 - 1` | never a valid revision |

**Member size check.** A member whose `identity` is longer than 256 bytes is
refused with `identity_too_large`; otherwise one whose `device` is longer than
64 bytes is refused with `device_too_large`. Empty identities and empty devices
are accepted (decision 0137, item 16).

**Largest valid values.** The three whole-input bounds (4,096, 2,048 and 8,192)
are above every valid value, so no valid input reaches them; the vectors pin each
by an over-bound input (section 14).

| Format | Largest valid encoding |
| --- | --- |
| roster | 3,048 bytes (eight members with 256-byte identities and 64-byte devices, and the authority likewise) |
| application context | 1,784 bytes (256/64-byte sender and recipient, 1,024-byte payload) |
| invitation bootstrap | 3,497 bytes (largest roster, 256/64-byte target) |
| invitation acceptance, revocation | 110 bytes (fixed) |
| group payload | 3,526 bytes (a group payload holding the largest bootstrap) |

## 3. Refusals

A decoder returns either a value or exactly one **refusal**. The vector file
names refusals by the `reason` labels below.

| Reason | Meaning |
| --- | --- |
| `malformed` | a short read, a wrong domain, a wrong fixed length, an unknown tag or flag value, a length prefix that disagrees with the input, trailing bytes, a group payload input longer than 8,192 bytes, or (when encoding) a value too long for its `lp16` prefix |
| `non_canonical` | the fields parse but list members or recipients are not strictly ascending, or two entries share an identity |
| `unsupported_policy` | a policy version other than 1 |
| `reserved_revision` | a revision equal to `2^64 - 1` |
| `invalid_genesis` | a revision-0 roster that is not a one-member, open, zero-predecessor roster of its authority |
| `too_many_members` | more than 8 members or recipients |
| `payload_too_large` | an application payload longer than 1,024 bytes |
| `identity_too_large` | a member identity longer than 256 bytes |
| `device_too_large` | a member device longer than 64 bytes |
| `roster_too_large` | a roster input longer than 4,096 bytes |
| `context_too_large` | an application-context input longer than 2,048 bytes |
| `conflict` | the parts of an invitation bootstrap disagree with each other |
| `empty_recipients` | an intent with no recipients |

**Order.** Each decoder below lists its steps in order. The refusal is the one
of the **first failing step**, so an input with several faults has one
well-defined refusal. Whether an input is accepted does not depend on the order.
Steps marked *cannot fail* are unreachable given the earlier steps; they are
listed because an implementation that reorders the steps needs to know that.

**Canonical form.** For every value the encoder produces exactly one byte
string, and a decoder accepts exactly the strings the encoder produces:
`encode(decode(b)) = b` for every accepted `b`, and `decode(encode(v)) = v` for
every valid `v`. A decoder MUST NOT accept a second spelling of any value.

**Encoders.** An encoder is given values of the types this page names: fixed
fields (group ID, invitation ID, digests) of their fixed length, integers within
their width, a payload tag from 1 to 5. What an encoder does with anything else
is outside this page, since a typed interface cannot hold such a value. An
encoder MUST NOT write bytes that its own decoder refuses. For a value of those
types it refuses what the "Encoding" paragraph of its section lists, with the
reasons given there, and those are the reasons the decoder gives for the same
fault. For the roster, context, acceptance and revocation these are the checks
the decoder makes on the parsed value; for the bootstrap and the intent they are
the decoder's checks in the decoder's order (sections 7 and 11); the payload's
encoder makes the checks of the variant its tag names (section 10). For a value
with several faults the order is the one the section states, which is not always
the order in which a decoder reads them (a decoder size-checks a member as it
reads it; sections 5 and 6 give the orders of the roster and the context). A
refused value produces no bytes.

## 4. What the bytes do not decide

A wire-valid value is not necessarily acceptable to the group policy. The
decoders above check structure, bounds and canonical form; they do not check
which peer sent the bytes, whether a digest is the commitment of anything, or
whether the value fits the receiver's current state. In particular a wire-valid
roster may have an authority that is not among its members, or no members at
all (revision 1 or later); the roster view (a later slice) refuses those. A
wire-valid intent may name its own sender among its recipients (OP-6). Section 13
lists the bindings a receiver checks before it acts on a decoded value.

## 5. Roster preimage

The canonical bytes of one accepted roster revision. Its commitment (section 13)
is the `predecessor_digest` of the next revision.

**Layout** (in order):

| Field | Encoding | Notes |
| --- | --- | --- |
| domain | `"Tacenta Group Roster v1"` (23 bytes) | |
| group ID | `lp32(group_id)` | the length is always 16 |
| revision | `u64` | not `2^64 - 1` |
| predecessor digest | `lp32(digest)` | the length is always 32; 32 zero bytes at revision 0 |
| authority | member, long form | |
| policy version | `u32` | 1 |
| closed | 1 byte | 0 (open) or 1 (closed) |
| member count | `u32` | at most 8 |
| members | `count` members, long form | strictly ascending in member order |

Total length: `104 + len(authority.identity) + len(authority.device)` plus, for
each member, `8 + len(identity) + len(device)`.

**Decoding** `decode_roster(input)`, in order:

1. If `len(input) > 4096`: `roster_too_large`.
2. `read(23)` MUST equal the domain, else `malformed`.
3. `read_lp32()` is the group ID; its length MUST be 16, else `malformed`.
4. `read(8)` is the revision.
5. `read_lp32()` is the predecessor digest; its length MUST be 32, else
   `malformed`.
6. `read_member()` is the authority (including its size check).
7. `read(4)` is the policy version.
8. `read(1)` is `closed`; a value other than 0 or 1 is `malformed`.
9. `read(4)` is the member count; a count above 8 is `too_many_members`, before
   any member is read.
10. `read_member()`, `count` times.
11. If any input remains: `malformed`.
12. Validate the roster value (**V-roster**), in order:
    1. revision equal to `2^64 - 1`: `reserved_revision`;
    2. policy version other than 1: `unsupported_policy`;
    3. revision 0 and any of: the predecessor digest is not 32 zero bytes,
       `closed` is 1, the member list is not exactly one member equal to the
       authority (identity and device both equal): `invalid_genesis`;
    4. more than 8 members: `too_many_members` (*cannot fail* here: step 9);
    5. the size check of section 2 on the authority (*cannot fail* here: step 6);
    6. for each member in order: the size check of section 2 (*cannot fail* here:
       step 10); then, if it is not the first and the previous member is not
       strictly less in member order, `non_canonical`; then, if its identity
       equals the identity of any earlier member, `non_canonical` (once the order
       holds for every earlier pair, only the previous member can share the
       identity, so the two tests differ only in which input reaches the second);
    7. an encoding longer than 4,096 bytes: `roster_too_large` (*cannot fail*
       here: step 1).

**Encoding** runs V-roster on the value (steps 4, 5 and 6 can fail there; step 7
cannot either, since the largest valid roster is 3,048 bytes) and then writes the
layout. It refuses with the same reasons.

**Notes.** A revision above 0 places no rule on the authority or the count: the
authority need not be a member and there may be no members. Identities must be
distinct, so with member order the device only ever breaks a tie that the
identity rule then refuses; in a valid roster the order is the strictly
ascending order of the identities alone (decision 0136).

## 6. Application context

The authenticated plaintext context of one application message from one sender
to one recipient. Its commitment (section 13) is what a receiver deduplicates
on.

| Field | Encoding | Notes |
| --- | --- | --- |
| domain | `"Tacenta Group Application v1"` (28 bytes) | |
| group ID | `lp32(group_id)` | length 16 |
| revision | `u64` | not `2^64 - 1` |
| roster digest | `lp32(digest)` | length 32 |
| sender | member, long form | |
| recipient | member, long form | |
| logical sequence | `u64` | any value |
| payload | `lp32(payload)` | at most 1,024 bytes |

Total length: `120 + len(payload)` plus the identity and device lengths of the
sender and the recipient.

**Decoding** `decode_context(input)`, in order:

1. If `len(input) > 2048`: `context_too_large`.
2. `read(28)` MUST equal the domain, else `malformed`.
3. `read_lp32()` is the group ID; length 16, else `malformed`.
4. `read(8)` is the revision.
5. `read_lp32()` is the roster digest; length 32, else `malformed`.
6. `read_member()` is the sender.
7. `read_member()` is the recipient.
8. `read(8)` is the logical sequence.
9. `read_lp32()` is the payload.
10. If any input remains: `malformed`.
11. Validate the context value (**V-context**), in order: revision equal to
    `2^64 - 1`: `reserved_revision`; payload longer than 1,024:
    `payload_too_large`; the size check of section 2 on the sender and then on
    the recipient (*cannot fail* here: steps 6 and 7); an encoding longer than
    2,048 bytes: `context_too_large` (*cannot fail* here: step 1).

**Encoding** runs V-context on the value and then writes the layout. Its
payload check therefore comes before its member size checks, the reverse of the
order in which a decoder meets them.

**Notes.** The sender and the recipient may be equal. The logical sequence has
no reserved value.

## 7. Invitation bootstrap

The authority's invitation to one target, with the exact source roster it names.
It has **no input bound of its own** (OP-5) and uses **short-form** framing for
the target and no framing at all for the IDs and the digest (OP-2, OP-3: kept as
they are in version 1).

| Field | Encoding | Notes |
| --- | --- | --- |
| domain | `"Tacenta Group Invitation Bootstrap v1"` (37 bytes) | |
| invitation ID | `raw(16)` | first |
| group ID | `raw(16)` | second: the reverse of sections 8 and 9 |
| target identity | `lp16(identity)` | |
| target device | `lp16(device)` | |
| source revision | `u64` | not `2^64 - 1` |
| source roster digest | `raw(32)` | |
| policy version | `u32` | 1 |
| expires at | `u64` | any value; logical time, no clock mapping |
| source roster | `lp32(roster preimage)` | a complete section 5 value |

**Decoding** `decode_bootstrap(input)`, in order:

1. `read(37)` MUST equal the domain, else `malformed`.
2. `read(16)` is the invitation ID; `read(16)` is the group ID.
3. `read_lp16()` is the target identity; `read_lp16()` is the target device.
   Neither is size-checked yet.
4. `read(8)` is the source revision.
5. `read(32)` is the source roster digest.
6. `read(4)` is the policy version.
7. `read(8)` is `expires_at`.
8. `read_lp32()` is the roster bytes; they MUST decode as a roster
   (`decode_roster`, section 5), and any refusal of that decoder is the refusal
   here, including `roster_too_large` for more than 4,096 bytes.
9. If any input remains: `malformed`.
10. Validate the invitation, in order: source revision equal to `2^64 - 1`:
    `reserved_revision`; policy version other than 1: `unsupported_policy`;
    target identity longer than 256: `identity_too_large`; target device longer
    than 64: `device_too_large`.
11. Validate the bootstrap, in order: the invitation's group ID differs from the
    roster's group ID: `conflict`; the source revision differs from the roster's
    revision: `conflict`; the policy version differs from the roster's:
    `conflict` (*cannot fail*: both are 1 after the earlier steps).

**Encoding** makes the decoder's checks on the value, in the decoder's order, and
refuses with the decoder's reasons:

1. any refusal of V-roster on the source roster (section 5, step 12; the decoder
   meets it at step 8);
2. the checks of step 10 on the invitation's own fields: a source revision equal
   to `2^64 - 1`, `reserved_revision`; a policy version other than 1,
   `unsupported_policy`; a target identity longer than 256, `identity_too_large`;
   a target device longer than 64, `device_too_large`;
3. the checks of step 11: an invitation group ID that differs from the roster's,
   a source revision that differs from the roster's, a policy version that
   differs from the roster's (*cannot fail*: both are 1 after 1 and 2), each
   `conflict`.

It then writes the layout. The two `lp16` prefixes cannot overflow, since a target
has at most 256 and 64 bytes after step 2. (An implementation whose invitation
record carries a status also refuses one that is not pending, as `conflict`,
with the checks of step 3; the bytes carry none.) So a reserved source revision
or a policy version other than 1 is named for what it is (`reserved_revision`,
`unsupported_policy`) even when the roster carries a different value, and is never
reported as a `conflict`; and the roster's own faults come first, as they do on
decoding.

**Notes.** The digest field is not checked against the roster here; section 13
says who does. The target need not differ from the roster's authority or
members.

## 8. Invitation acceptance

The target's acknowledgement of one bootstrap. Fixed length: 110 bytes.

| Field | Encoding | Notes |
| --- | --- | --- |
| domain | `"Tacenta Group Invitation Acceptance v1"` (38 bytes) | |
| group ID | `raw(16)` | first |
| invitation ID | `raw(16)` | second |
| source revision | `u64` | not `2^64 - 1` |
| source roster digest | `raw(32)` | |

**Decoding** `decode_acceptance(input)`, in order:

1. `read(38)` MUST equal the domain, else `malformed`.
2. `read(16)` is the group ID; `read(16)` is the invitation ID.
3. `read(8)` is the source revision; `read(32)` is the digest.
4. If any input remains: `malformed`.
5. Source revision equal to `2^64 - 1`: `reserved_revision`.

**Encoding** refuses a reserved revision and writes the layout.

## 9. Invitation revocation

The authority's terminal revocation of one bootstrap. The layout is that of
section 8 with a different domain string, `"Tacenta Group Invitation Revocation
v1"` (38 bytes), and the same 110-byte length, the same steps and the same
refusals. The two domain strings differ in one word, and the group payload tag
(section 10) differs as well, so an acceptance is not a revocation under either.

## 10. Group payload

The plaintext of a pairwise message carried in a `group`-class relay envelope:
a domain, a tag that selects the parser, and one length-framed value. The
receiver decodes the payload once and the tag chooses the parser (decision 0121).

| Field | Encoding | Notes |
| --- | --- | --- |
| domain | `"Tacenta Group Payload v1"` (24 bytes) | |
| tag | 1 byte | 1 to 5 |
| length | `u32` | the length of `value` |
| value | `raw(length)` | the encoding of the variant the tag names |

| Tag | Variant | Value |
| --- | --- | --- |
| 1 | application | application context (section 6) |
| 2 | roster | roster preimage (section 5) |
| 3 | invitation bootstrap | section 7 |
| 4 | invitation acceptance | section 8 |
| 5 | invitation revocation | section 9 |

The tag values 0 and 6 to 255 are unassigned and refused.

**Decoding** `decode_payload(input)`, in order:

1. If `len(input) > 8192`, or the input does not begin with the 24-byte domain:
   `malformed`.
2. `read(1)` is the tag; if the input ends first, `malformed`.
3. `read(4)` is the length; if fewer than 4 bytes remain, `malformed`.
4. The bytes that remain MUST number exactly `length`, else `malformed`
   (a short value, trailing bytes and a wrong length are all this step).
5. Dispatch on the tag: a tag outside 1 to 5 is `malformed`; otherwise the
   value is decoded by the decoder of the table, and **any refusal of that
   decoder is the refusal of the payload**, unchanged.

**Encoding** writes the domain, the tag, `u32(len(value))` and the value, where
the value is the variant's encoding (so it refuses what the variant's encoder
refuses), and refuses with `malformed` if the whole payload would exceed 8,192
bytes (*cannot fail* for a valid variant, whose largest payload is 3,526 bytes).

**Notes.** Because the payload bound is checked first and reported as
`malformed`, while the bounds of the variants have their own reasons, a
tag-1 or tag-2 input of exactly 8,192 bytes is refused by its variant
(`context_too_large`, `roster_too_large`) and one of 8,193 bytes is refused as
`malformed`; the vectors use that to pin the bound.

## 11. Logical-send intent

The immutable record of one logical send, written before any per-recipient
encryption and read again when the client recovers. Unlike the formats above it
is not exchanged between peers (it is the body of a local `TCGI` record); it is
in this slice for the reasons in decision 0149. It has **no input bound of its
own**.

| Field | Encoding | Notes |
| --- | --- | --- |
| domain | `"Tacenta Group Logical Send v1"` (29 bytes) | |
| group ID | `lp32(group_id)` | length 16 |
| revision | `u64` | not `2^64 - 1` |
| sender | member, long form | |
| sequence | `u64` | any value |
| roster digest | `lp32(digest)` | length 32 |
| payload | `lp32(payload)` | at most 1,024 bytes |
| recipient count | `u32` | 1 to 8 |
| recipients | `count` members, long form | strictly ascending in member order, distinct identities |

Total length: `117 + len(payload)` plus the identity and device lengths of the
sender, plus for each recipient `8 + len(identity) + len(device)`.

**Decoding** `decode_intent(input)`, in order:

1. The input MUST begin with the 29-byte domain, else `malformed`.
2. `read_lp32()` is the group ID; length 16, else `malformed`.
3. `read(8)` is the revision.
4. `read_member()` is the sender.
5. `read(8)` is the sequence.
6. `read_lp32()` is the roster digest; length 32, else `malformed`.
7. `read_lp32()` is the payload; longer than 1,024: `payload_too_large`.
8. `read(4)` is the recipient count: 0 is `empty_recipients`, above 8 is
   `too_many_members`, both before any recipient is read.
9. `read_member()`, `count` times.
10. If any input remains: `malformed`.
11. For each recipient in order, if it is not the first and the previous
    recipient is not strictly less in member order, or its identity equals the
    identity of an earlier recipient: `non_canonical`.
12. Revision equal to `2^64 - 1`: `reserved_revision`.

**Encoding.** An intent is produced from a logical send, which is built from an
open roster, a sender and recipients that are members of it, at least one
recipient and a payload of at most 1,024 bytes. An encoder does not rely on that
construction (a caller of the Rust crate can change the fields after it, and the
construction does not size-check a member or count the recipients). It makes the
decoder's checks on the value, in the decoder's order, and refuses with the
decoder's reasons:

1. a sender identity longer than 256, `identity_too_large`; then a sender device
   longer than 64, `device_too_large` (step 4);
2. a payload longer than 1,024, `payload_too_large` (step 7);
3. no recipients, `empty_recipients`; more than 8, `too_many_members` (step 8);
4. for each recipient in order, the size check of 1 (step 9);
5. for each recipient in order, if it is not the first and the previous
   recipient is not strictly less in member order, or its identity equals the
   identity of an earlier recipient, `non_canonical` (step 11);
6. a revision equal to `2^64 - 1`, `reserved_revision` (step 12).

Otherwise it writes exactly the layout above.

## 12. Open points

Each item is something the code does that no decision record explains, or that
disagrees with one. This page follows the code (the only implementation) and
does not choose; a human decision on an item may change the code, a decision
record or this page. Four items were decided on 2026-09-30 and are recorded first,
with what the decision changed; the other four are still open.

### Decided

**OP-1. Authority and sender framing in the decision records: the code's form is
version 1.** Decision 0092 wrote the roster's authority as `lp(authority_binding)`
and decision 0105 wrote the intent's sender as `lp(sender_binding)`, each a single
length-prefixed field. The code writes each as a long-form member: two
length-prefixed fields, identity then device, with no outer length, and this page
states that form. It is the specified one. Decisions 0092 and 0105 carry an
amendment note and the corrected layout text. No byte changed.

**OP-2. Three framing conventions: kept in version 1.** The roster, context and
intent frame fixed-size fields (group ID, digest) with `lp32` and members in long
form. The bootstrap carries the target in short form (`lp16`) and the group ID,
invitation ID and digests as raw bytes; acceptance and revocation carry raw bytes
only. Changing them would change bytes for no gain, so they stay. The cost is that
an implementation MUST NOT assume one convention across the formats: two
implementations that do will disagree. Take each layout from its own section.
Recorded in decision 0149.

**OP-3. Field order of the invitation ID and the group ID: kept in version 1.** The
bootstrap writes invitation ID then group ID; acceptance and revocation write group
ID then invitation ID. Changing it would change bytes for no gain. The cost is the
same as for OP-2: an implementation MUST NOT assume one order across the three
formats. Recorded in decision 0149.

**OP-4. The bootstrap encoder checked less than its decoder: fixed.** The decoder
refused a target identity above 256 bytes or device above 64 bytes
(`identity_too_large`, `device_too_large`), but `InvitationBootstrap::encode` did not,
so a value built from the public fields of `Invitation` with a 300-byte identity
encoded to 546 bytes that the same crate then refused; it also skipped step 10 of
section 7, so a reserved source revision or a policy version other than 1 was
refused as `conflict` (or by the roster's own refusal) where the decoder says
`reserved_revision` or `unsupported_policy`. The encoder now makes the decoder's
checks in the decoder's order (section 7, Encoding). The logical-send encoder
(`LogicalSend::encode_intent`) had the same defect for a member's size, the number
of recipients and a field changed after construction, and is fixed the same way
(section 11, Encoding); this page had said an intent encoder needs no refusals.
Section 3 states the rule for every encoder, and the vector file holds it: each
`encode_refuse` vector has a decoder twin of the same name and reason (section 14).
The same rule was applied to two local state encoders that this page does not
cover (decision 0149).

### Still open

**OP-5. Several decoders have no input bound.** The roster (4,096), context
(2,048), payload (8,192) and receiver state have bounds checked before parsing
(decision 0104). The bootstrap, acceptance, revocation and intent decoders have
none: an oversized input is refused only after a field has been copied out of
it, so memory is bounded by the length of the input and not by a constant. When
they arrive inside a group payload the 8,192 bound applies first.

**OP-6. Nothing says whether a sender may be among its recipients.** The
intent codec accepts a sender that also appears in the recipient list, and
`LogicalSend::new` builds such a value from a roster that lists the sender.
Decision 0105 says only that recipient bindings follow the roster order.

**OP-7. `expires_at` and the sequence have no unit.** Expiry is a logical time
that the caller supplies; the wire carries a `u64` and nothing maps it to a
clock (decision 0093, `docs/claims.md`). The logical sequence has no reserved
value and no allocation rule on the wire (decision 0138 owns the allocation).

**OP-8. Version evolution is by domain string only.** Every domain ends in
`v1`. There is no version field: a future incompatible layout is a new domain,
and a `v1` reader refuses it as `malformed`. Decision 0118 says a "versioned
capability rule" would be needed for new control types; none exists. The tags
6 to 255 are unassigned.

## 13. Commitments and the bindings a receiver checks

This section is informative: it states the inputs of the two commitments and the
comparisons a receiving client makes after a successful decode. Neither is part
of the codecs.

**Commitments.** tacenta-core owns the primitive and its labels
(`groups.rs` at the core revision the workspace pins; decisions 0092 and 0094).

    roster_commitment(preimage)  = SHA-256("Tacenta:group:roster-commitment:v1" || 0xFF || preimage)
    payload_commitment(context)  = SHA-256("Tacenta:group:payload-commitment:v1" || 0xFF || context)

`preimage` is the exact roster bytes of section 5 (not the group payload that
carries them) and `context` is the exact application-context bytes of section 6.
Each result is 32 bytes.

**Where each digest field is used.**

- A roster's `predecessor_digest` is the `roster_commitment` of the previous
  revision's preimage (32 zero bytes at revision 0).
- A context's `roster_digest` is the `roster_commitment` of the accepted roster
  it was sent under.
- A bootstrap's `source_roster_digest` is the `roster_commitment` of its
  embedded source roster, that is of the exact bytes inside `lp32(roster)`.
  A receiver computes that commitment and refuses the bootstrap if it differs;
  the decoder does not.
- The `source_roster_digest` of an acceptance and of a revocation is the same
  value as in the bootstrap they answer.
- An intent's `roster_digest` is the `roster_commitment` of the roster it was
  built under.
- A receiver deduplicates application contexts on `payload_commitment(context)`.

**Other bindings** (the group coordinator, a later slice): the receiver takes
the authenticated sender from the pairwise layer, never from a field; it
requires a bootstrap's source roster to be open, to name the authenticated peer
as its authority, and the target to be the local member; it requires a
context's sender to be the authenticated peer and its recipient the local
member. Each of these is checked after a successful decode.

## 14. Vectors

`contracts/vectors/group-wire-v1.json` holds the vectors of this page. Its
`format` is `group-wire-v1`. It is **not** generated from the Lean model, which
has no bytes; it is generated by a Rust test that builds every byte string from
the rules of this page with a hand-written builder (not with the production
encoders), and it is replayed by that test against the production encoders and
decoders and, independently, by a reader written from this page alone
(`tooling/group_wire_reference.py`, run by `tooling/check-group-wire-vectors.sh`).
Decision 0149 explains why this differs from decision 0003.

**File layout.** A JSON object with `format`, `limits`, `domains`, `commitments`
and `vectors`. Each vector is one line. A `u64` is a decimal string (no sign, no
leading zero except `"0"`); a `u32`, a count or a tag is a JSON number; byte
strings are lowercase hexadecimal of even length.

- `limits` holds the constants of section 2 under the keys `group_id_len`,
  `invitation_id_len`, `digest_len`, `policy_version`, `max_members`,
  `max_identity_len`, `max_device_len`, `max_payload_len`, `max_roster_len`,
  `max_context_len`, `max_group_payload_len` (JSON numbers) and
  `reserved_revision` (a decimal string).
- `domains` maps the format names below to their domain strings.

**A vector** has `name` (unique, `format/case`; an `encode_refuse` name starts
`format/encode-`), `format` (one of `roster`, `context`, `bootstrap`,
`acceptance`, `revocation`, `payload`, `intent`) and `result`:

| `result` | Other members | A reader must |
| --- | --- | --- |
| `valid` | `bytes`, `fields` | decode `bytes` to `fields`, and encode `fields` to exactly `bytes` |
| `refuse` | `bytes`, `reason` | refuse `bytes` with `reason` |
| `refuse_prefixes` | `bytes`, `reason` | refuse every proper prefix of `bytes` (lengths 0 to `len - 1`) with `reason` |
| `encode_refuse` | `fields`, `reason` | refuse to encode `fields` with `reason` |

`bytes` may be followed by `pad_to` (a number, never below the length of
`bytes`, and only on `refuse`): the input is `bytes` followed by as many `00`
bytes as it takes to make it exactly `pad_to` bytes long. `bytes` may be empty.
Every `fields` value in the file satisfies the encoder-input rule of section 3,
and every `valid` vector of any format, the intent included, is one whose fields
satisfy the decoding rules.

**Encoder refusals are paired with decoder refusals.** An `encode_refuse` vector
named `format/encode-x` has a `refuse` vector named `format/x` with the same
`reason`, so that an encoder cannot check less than its decoder (section 3)
without a vector failing. The one exception is
`context/encode-precedence-encode-checks-payload-before-sender-size`, the order of
section 6 that differs from the decoder's. The intent's encoder vectors state one
fault each: the Rust replay builds the value with `LogicalSend::new`, which judges
some faults (the revision, an empty recipient list, the payload, a recipient's
membership and order) before the encoder does, so no vector pins the order of two
intent faults; the crate's unit tests do.

`fields` per format (a member is `{"identity": hex, "device": hex}`; keys are
compared as a set, not in order):

- `roster`: `group_id`, `revision`, `predecessor_digest`, `authority`,
  `policy_version`, `closed` (boolean), `members` (list).
- `context`: `group_id`, `revision`, `roster_digest`, `sender`, `recipient`,
  `logical_sequence`, `payload`.
- `bootstrap`: `invitation_id`, `group_id`, `target` (a member),
  `source_revision`, `source_roster_digest`, `policy_version`, `expires_at`,
  `source_roster` (the `roster` fields).
- `acceptance`, `revocation`: `group_id`, `invitation_id`, `source_revision`,
  `source_roster_digest`.
- `payload`: `tag`, `value` (the fields of the variant the tag names).
- `intent`: `group_id`, `revision`, `sender`, `sequence`, `roster_digest`,
  `payload`, `recipients` (list of members).

A `commitments` entry is `{"kind": "roster" | "payload", "preimage": hex,
"digest": hex}`: `digest` MUST equal the commitment of section 13 over
`preimage`. Kind `roster` is `roster_commitment` over roster bytes; kind
`payload` is `payload_commitment` over the bytes of an application context
(section 6), not over a group payload (section 10). A valid bootstrap vector may
carry a `source_roster_digest` that is not the commitment of its embedded
roster: the codec does not check it (section 13).

**What the vectors pin, and what they do not.** They pin the layouts, the domain
strings, the tag values, the refusals named above at the edges of the bounds
(both sides, by literal number, except the unreachable bounds below), the
first-versus-later-entry classes for member and recipient lists, the member
order, and the handling of empty and maximal fields. A vector named
`precedence-...` pins the order of two checks; those orders are stated in the
steps above and are not otherwise meaningful. They do not pin: an input with
several faults beyond those precedence vectors; the `expires_at` and sequence
meanings; anything in sections 12 and 13 other than the digest computation; the
order of two faults of an intent encoder (above); the unreachable bounds of the
encoders (the roster encoding of 4,096 bytes, the context encoding of 2,048, the
payload encoding of 8,192, and the `lp16` length of a bootstrap target, which no
target above 256 bytes reaches); and any local record.

## 15. Worked examples

The genesis roster of the vectors (`roster/genesis`, 124 bytes): group ID
`bounded-group-id`, authority and only member `alice` with device `01`.

    546163656e74612047726f757020526f73746572207631   domain "Tacenta Group Roster v1"
    00000010                                         lp32(group_id): length 16
    626f756e6465642d67726f75702d6964                 group_id "bounded-group-id"
    0000000000000000                                 revision 0
    00000020                                         lp32(predecessor_digest): length 32
    00 x 32                                          32 zero bytes
    00000005 616c696365                              authority identity "alice"
    00000001 01                                      authority device 01
    00000001                                         policy version 1
    00                                               closed: open
    00000001                                         member count 1
    00000005 616c696365 00000001 01                  member alice, device 01

An invitation acceptance (`acceptance/revision-0`, 110 bytes), which has no
framing at all after its domain:

    546163656e74612047726f757020496e7669746174696f6e20416363657074616e6365207631
                                                     domain "Tacenta Group Invitation Acceptance v1"
    626f756e6465642d67726f75702d6964                 group_id
    09090909090909090909090909090909                 invitation_id
    0000000000000000                                 source revision 0
    e1d3bb2c88e0e146e1587d18d8ea9c8b45bee978390dcd8d3bc3f264b4927ae6
                                                     source roster digest (roster_commitment of the roster above)

The same acceptance as a group payload (`payload/tag-4-invitation-acceptance`,
139 bytes) is `546163656e74612047726f7570205061796c6f6164207631` (the domain
`Tacenta Group Payload v1`), `04` (the tag), `0000006e` (the length, 110), and
the 110 bytes above.
