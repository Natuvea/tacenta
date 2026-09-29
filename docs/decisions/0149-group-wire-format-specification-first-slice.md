# 0149 — group wire formats: the first slice of their specification

> Clarifies 0092, 0094, 0105, 0118, 0121, 0125 and 0126 (it gives the bytes
> they leave out). Amends 0118 (there are five payload variants, not two). Does
> not amend 0003, which it departs from for one vector file, below.

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

1. The page is the authority. It states each layout, each bound and every
   refusal, in the order a decoder checks them.
2. `crates/tacenta-group/tests/group_wire_vectors.rs` holds a hand-written
   builder that writes every byte string field by field from the page and never
   calls a production encoder. It writes the vector file, and a second test fails
   when the committed file differs from what the builder writes.
3. The same file replays the committed vectors, not the builder, against the
   production decoders and encoders.
4. `tooling/group_wire_reference.py` is a reader written from the page and the
   vector file alone, by an author who had not seen the Rust, and
   `tooling/check-group-wire-vectors.sh` replays every vector through it. CI runs
   both.

The direction of decision 0003 is kept: the specification text leads and the
code conforms. What changes is that the executable specification is a builder
and a second reader rather than a proved model.

**Open points.** Where the code does something no record explains, or
disagrees with a record, the page follows the code and lists the point (OP-1 to
OP-8 in section 12) rather than choosing. The page states no compatibility
promise: nothing in the group profile has been released.

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
  reader in Python, written by different passes over the text, gives two
  independent readings of the page.
- **Do nothing until the open points are decided.** The bytes are stable enough
  to state, and stating them is how the open points were found.

## Why

Interoperability and the trust boundary are decided by the formats that cross
peers, and those are also the small, stateless, well-bounded ones: each has a
domain string, fixed fields and explicit bounds, and none depends on
coordinator state. The decoders already have a structure-aware robustness test
(`tests/codec_robustness.rs`) and round-trip tests; what was missing was the text
a second implementation would need and vectors that pin the bytes. Writing the
page from the code and then having it replayed by a reader that saw only the
page is the cheapest test that the page is enough.

## What would reopen this

- A second implementation, which turns open points OP-1 to OP-3 from questions
  into interoperability failures.
- A decision on any open point that changes a layout (new domain strings, new
  vectors, a new record).
- The Lean model gaining bytes and a human review: then the vectors should be
  generated from it under decision 0003 and the Rust builder retired.
- A store other than the client's own reading the local records, or those
  records stopping changing: the second slice.
- A multi-device, larger or production profile, which needs versioned successors
  of every format here.
