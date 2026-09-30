# 0149 — group wire formats: the first slice of their specification

> Clarifies 0092, 0094, 0105, 0118, 0121, 0125 and 0126 (it gives the bytes
> they leave out). Amends 0118 (there are five payload variants, not two), and
> 0092 and 0105 (2026-09-30: the code's two-field form of the authority and the
> sender is the specified one). Does not amend 0003, which it departs from for one
> vector file, below. Corrected 2026-09-30: the direction of the work (below) and
> what the second reader is are stated as they were, and the order in which each
> encoder refuses a value with several faults is recorded.

## Decision

The bounded group-chat experiment has eleven domain strings and fourteen record
tags and no specification of any of them. This record splits the work in two and
does the first part.

**First slice.** The formats that a second implementation must produce and that
an attacker controls, plus the one record that crosses a persistence boundary:
the group payload with its five tags, the roster preimage, the application
context, the invitation bootstrap, acceptance and revocation, and the
logical-send intent. They are specified in `spec/group-wire-formats.md`, with
byte vectors in `contracts/vectors/group-wire-v1.json`. The inventory of every
format, slice or not, is `docs/group-wire-format-inventory.md`.

**Later slice, not done here.** The local records: the receiver, roster-view,
invitation-book and control-outbox states, the `TCG?` transcript records and the
`TCOP` snapshot framing. They are product-owned local formats, read only by the
client that wrote them, and they are the part of the profile that changed most
often while it was built (a receive record changed in 0133, two record kinds
were added by 0142 and 0145, the control-outbox state is already `v2`). A
specification and vectors for them would be out of date by the next change.
They get their own record when they stop moving or when a store other than this
client's must read them.

**The intent is the one exception to that split.** The logical-send intent (the
body of a `TCGI` record) is a local record, and by the rule above it would wait.
It is in this slice because it is public API of `tacenta-group` beside the
other codecs, its recovery decoder is where a stored value re-enters the client
and the store is unsealed, and its recipient order and payload bound are the
same rules as the roster's and the context's. If the split should be strict, the
intent moves to the later slice and section 11 of the page moves with it.

**How the vectors are made.** The Lean model has no bytes (decision 0137,
item 11), so decision 0003's route (Lean generates, Rust conforms) is not
available for this file. Instead:

1. The page states each layout, each bound and every refusal, in the order a
   decoder checks them. It was written from the code (below), not the other way
   round.
2. `crates/tacenta-group/tests/group_wire_vectors.rs` holds a hand-written
   builder that writes every byte string field by field from the page and never
   calls a production encoder. It writes the vector file, and a second test fails
   when the committed file differs from what the builder writes.
3. The same file replays the committed vectors, not the builder, against the
   production decoders and encoders.
4. `tooling/group_wire_reference.py` is a second program that replays the vectors,
   and `tooling/check-group-wire-vectors.sh` runs it. It is a differential oracle,
   not an independent implementation of the page. A separate agent (not a person)
   first wrote it from the page and the vector file, after printing the name and
   expected reason of every vector then in the file; it was edited in a second
   pass, and its bootstrap and intent encoders were revised by the implementer of
   the encoder change, not by a fresh reader. The agent's reports are not in
   this repository, so that it did not read the Rust cannot be checked from here.
   CI runs both replays.

**Direction.** Decision 0003 has the specification lead and the code conform.
That is not how this slice was made. The page was written from the code as it was
at revision `2062899` and says so; the code changed afterwards only where the
decision of 2026-09-30 on OP-4 said that an encoder must refuse what its decoder
refuses, and the page was then changed to state that. So the direction of 0003 is
not kept for this file, and this record does not claim that it is. What the
executable specification is here is a builder and a second program rather than a
proved model. Which of the page and the code prevails when they disagree is not
decided by this record. A disagreement between the code (or the second program)
and the vectors fails a check that CI runs; a disagreement between the text of
the page and the vectors is found only by reading.

**Open points.** Where the code does something no record explains, or
disagrees with a record, the page follows the code and lists the point (OP-1 to
OP-8 in section 12) rather than choosing. Four were decided on 2026-09-30, below;
OP-5 to OP-8 remain open. The page states no compatibility promise: nothing in
the group profile has been released.

## Decisions on the open points (2026-09-30)

**OP-1: the code's form is wire version 1.** The roster's authority (0092) and the
intent's sender (0105) are each written as a member entry: `lp(identity)` then
`lp(device)`, with no length around the pair. Decisions 0092 and 0105 said
`lp(authority_binding)` and `lp(sender_binding)`; they carry a dated amendment note
and the corrected layout text, and the earlier wording stays readable in the note.
Considered: change the code to one length-prefixed field. Rejected: it changes the
bytes of the roster preimage (and so every roster commitment and every vector that
chains through one) and of the intent, for no gain. No byte changes.

**OP-2 and OP-3: kept as accepted properties of version 1.** The framing
conventions differ between the formats (the roster, context and intent use `lp32`
around fixed-size fields; the bootstrap uses `lp16` for its target and raw bytes
for the IDs and digests; acceptance and revocation use raw bytes only), and the
bootstrap writes the invitation ID before the group ID where acceptance and
revocation write them the other way round. Considered: make them uniform.
Rejected: it changes the bytes of three invitation formats for no gain. The
trade-off is that an implementer must not assume one convention or one field order
across the formats, and must take each layout from its own section; two
implementations that do assume one will disagree. The page says so at each place.
A second implementation reporting an interoperability failure here would reopen
this.

**OP-4: fixed in the code.** An encoder writes only what its own decoder accepts,
and refuses what the decoder refuses with the reason the decoder gives. In
`tacenta-group`:

- `InvitationBootstrap::encode` now makes the decoder's checks in three groups in
  the decoder's order: the source roster, then the invitation's own fields (a
  reserved source revision, a policy version other than 1, a target identity above
  256 bytes or device above 64), then how the two fit together (`conflict`). Inside
  the first group the order is V-roster's, the order of `Roster::encode`, and not
  the order in which `Roster::decode` meets the faults of the same roster (see
  "The order of an encoder's refusals", below). Before, it skipped the target size
  check, so a 300-byte identity encoded to bytes the same crate refused, and it
  reported a reserved revision or a wrong policy version as `conflict`.
- `LogicalSend::encode_intent` made none of the decoder's checks and relied on
  `LogicalSend::new`, which does not size-check a member or count the recipients,
  and whose `payload` and `id` fields are public. It now makes the decoder's
  checks in the order the decoder meets them (section 11, Encoding).
- Two local state encoders had the same defect and were fixed the same way, though
  this page does not specify them: `InvitationBook::encode_state` (a record whose
  fields `Invitation::new` would refuse, which `InvitationBook::create` lets in
  because the fields are public) and `GroupReceiver::encode_state` (a local member
  over the size limits).

No value the decoder accepts changes its bytes, and no value is refused that was
accepted and read back. The rule is held by tests: the vector file pairs each
`encode_refuse` vector with the decoder's refusal of the same fault, and
`crates/tacenta-group/tests/encoder_refusals.rs` states the rest. Considered: keep
the encoder as it was and document the gap. Rejected: a value written that cannot
be read back is a persistence hazard, most of all for the intent, which is written
before any send and read again at recovery. Considered: fix the bootstrap only.
Rejected: the same defect was in three other encoders. The tacenta-client record
and state encoders were not audited.

## The order of an encoder's refusals (recorded 2026-09-30)

A value with several faults is refused for the first fault in the order of its
encoder. This record states that order for each encoder, as the code has it; no
code and no byte changed in stating it. "The decoder's order", as OP-4 first
worded it, was shorthand, and it is exact for every encoder but three.

- **Roster** (`Roster::encode`): V-roster, section 5 step 12: the reserved
  revision, the policy version, the genesis rule, the member count, the
  authority's size, then each member in turn (its size, its place in the order, a
  repeated identity).
- **Application context**: V-context, section 6 step 11: the reserved revision,
  the payload, the sender's size, the recipient's size.
- **Invitation bootstrap**: the source roster, in V-roster's order; then the
  invitation's own fields; then how the invitation fits the roster.
- **Acceptance, revocation**: the reserved revision.
- **Group payload**: the variant's encoder, then the 8,192 bound.
- **Logical-send intent**: the sender's size, the payload, the number of
  recipients, each recipient's size, the order of the list, the revision.

The decoders of the roster, the context and the bootstrap's source roster judge
the authority's size, the member count and each member's size, or the sender's and
the recipient's size, as they read, before they run V-roster or V-context. For a
value with two faults, one of which such a check judges, the encoder and the
decoder of the same bytes therefore give different reasons: a reserved revision
and nine members are `reserved_revision` from the encoder and `too_many_members`
from the decoder. The other encoders meet faults in the order of their decoders.
Sections 3, 5, 6 and 7 of the page state the cases, and the vector file holds a
pair of vectors for each (section 14).

Considered: make the roster encoder, and so the bootstrap's, judge the read-time
checks first, so that the encoder and the decoder always agree on the reason.
Rejected: it changes which reason a value with several faults gets from
`Roster::encode` and from the encoders that call it, for no accepted value and no
byte, and V-roster's order is the order the code and the second program have. The
difference is pinned by vectors instead, so a change to either order fails a
check. Reopen this if a second implementation finds the difference a cost.

## The five questions

1. **Does this keep the trusted core small?** Yes. Nothing in tacenta-core
   changes. The page quotes the core's two commitment labels (`groups.rs` at the
   pinned core revision) and copies no code into it.
2. **Is the behaviour owned by a written specification?** It is, from this
   record: the page owns the bytes of the first slice, and the core's own
   specification owns the commitment primitive and its labels (0092). The local
   records still are not (above).
3. **Can the security claim be reproduced?** No security claim is made. The
   canonicality and refusal claims reproduce with
   `cargo test -p tacenta-group --test group_wire_vectors` and
   `bash tooling/check-group-wire-vectors.sh`, and the commitment entries with
   `cargo test --workspace the_group_wire_vectors_commitments`.
4. **Does it preserve wire compatibility with a named profile?** No named
   profile carries these formats. They are `v1` of an unreleased experiment;
   a human decision on an open point may change a layout, and it would then take
   a new domain string.
5. **Is this protocol functionality, or product coupling trying to enter the
   core?** Product policy bytes. The core hashes opaque bytes it is given and
   parses none of them; this record adds nothing to it.

## Considered

- **Specify all fourteen kinds of record at once.** Rejected: most of the bytes
  are local records that are still changing, and vectors for them would pin
  incidental layout.
- **Extend the Lean model with encoders and generate the vectors from it, as
  0003 does.** The model would need byte-level members, commitments and bounds
  it does not have, and a change to it needs the human review that the model has
  not had. Reopen when it does (below).
- **Generate the vectors from the production encoders.** Circular: the file
  would record what the code does and the code would agree with it.
- **Write the reader and the generator as one Python program.** A generator that
  is also the reader agrees with itself. Keeping the builder in Rust and the
  reader in Python, written in different passes over the text, gives two readings
  of the page. They are not independent: both follow the same page, which was
  written from the code, and the reader's first author had seen the names and
  reasons of the vectors.
- **Do nothing until the open points are decided.** The bytes are stable enough
  to state, and stating them is how the open points were found.

## Why

Interoperability and the trust boundary are decided by the formats that cross
peers, and those are also the small, stateless, well-bounded ones: each has a
domain string, fixed fields and explicit bounds, and none depends on
coordinator state. The decoders already have a structure-aware robustness test
(`tests/codec_robustness.rs`) and round-trip tests; what was missing was the text
a second implementation would need and vectors that pin the bytes. Writing the
page from the code and then having it replayed by a second program that was first
written from the page and the vectors is a cheap test that the page is enough to
reproduce the layouts and refusals. It cannot show that the code is right where
the code and the page share a choice.

## What would reopen this

- A second implementation, which turns the accepted framing and field-order
  differences (OP-2, OP-3) from a cost into interoperability failures.
- A decision on any open point (OP-5 to OP-8) that changes a layout (new domain
  strings, new vectors, a new record).
- The Lean model gaining bytes and a human review: then the vectors should be
  generated from it under decision 0003 and the Rust builder retired.
- A store other than the client's own reading the local records, or those
  records stopping changing: the second slice.
- A multi-device, larger or production profile, which needs versioned successors
  of every format here.
