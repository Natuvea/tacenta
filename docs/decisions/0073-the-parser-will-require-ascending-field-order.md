# 0073 — the parser will require ascending field order

## Decision

**`tacenta-core/protobuf` will refuse a message whose fields do not arrive in
strictly ascending field-number order.** Today it accepts any order, so
canonical emission — every accepted byte string is the encoding of what it
decodes to — is not yet established for this layer.

This is a decision about what the product accepts. It is recorded before it is
made, because the alternative readings are not a proof engineer's call.

## Why it is not yet established, and why that matters

The round-trip theorems this repository already has run encode-then-decode.
They constrain the encoder and say nothing about which byte strings the decoder
accepts. The property with content runs the other way:

> every accepted byte string is the encoding of what it decodes to

That is what makes an authenticator over exact bytes mean anything. Without it,
two distinct byte strings can decode to the same value, so a signature over one
does not pin the other, and "the bytes were authenticated" stops implying "the
message was".

`parse_ratchet_body` accepts fields in any order, while the encoder emits
ascending. So a reordered input that the parser accepts re-encodes
to *different* bytes, and the property cannot hold for a parser that accepts
any order. No amount of proof effort changes that; the format has to change.

`varint_canonical` already proves the corresponding property one level down, at
the primitive. The gap is at the message level.

## Why ascending, and why now

Accepting any order is a permissive default with no consumer: the encoder
emits ascending, so requiring ascending order on input affects no message this
product produces, and it is what makes canonical emission provable.

This is the same shape as decision 0072's class, seen from the other side: an
accommodation made for a reason that has since expired, still being paid for.

## What it does not do

**It does not make the theorem true by itself.** It makes it *provable*. The
proof is separate work and the claim ledger does not move until it lands.

**It is not a claim about interoperability.** Requiring ascending order narrows
what the product accepts. If message-layer interoperability is ever revived, a
peer emitting descending order would be refused, and this decision would be the
thing to revisit — which is why it is written down rather than absorbed into a
commit.

## Cost, stated plainly

`tacenta-core/protobuf` is **inside the verified zone**. Changing it re-runs the
Charon/Aeneas translation and re-opens every T1 and T3 theorem about it,
including `parse_ratchet_body_loop_refines`, `parse_prekey_body_refines` and
`oneEnvelopeField_refines`, along with the Lean model those refine against. The
parser change itself is small — carry the last field number and refuse a
non-increasing one — and the proof work around it is not.

The pinned Aeneas release is linux-x86_64 only, so the translation is
regenerated in CI rather than locally. Drift detection, the regenerated
translation as a downloadable artifact, and a local gate that refuses to report
health while the verification workflow is red are what make this a tractable
change rather than a blind one.

**This record is the decision. The implementation is not part of it** and should
land as its own change, with the translation regenerated and both tiers rebuilt
before `docs/claims.md` moves.

## Status

Decided. The blocking question is answered; what remains is proof work with a
settled premise.
