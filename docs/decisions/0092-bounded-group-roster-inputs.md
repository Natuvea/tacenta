# 0092 — bounded group roster inputs

## Decision

The bounded group experiment has a product-owned, canonical roster preimage.
A group ID is exactly 16 opaque bytes. A revision is an unsigned 64-bit
big-endian integer: genesis is zero, every successor is exactly one greater,
and the reserved value `u64::MAX` is refused. The first profile permits one
bound device per identity and at most eight member entries.

The preimage is:

```text
"Tacenta Group Roster v1" || lp(group_id) || u64be(revision)
|| lp(predecessor_digest) || lp(authority_binding) || u32be(policy_version)
|| closed || u32be(member_count) || members
```

`lp(x)` is a four-byte big-endian length followed by exactly `x`.
`closed` is one byte, zero or one. Genesis uses a 32-byte all-zero
predecessor digest; successors use the exact prior accepted digest. A member
entry is `lp(identity_bytes) || lp(device_bytes)`. Entries sort
lexicographically by the full `identity_bytes || device_bytes` tuple.
A duplicate full tuple, a second device for one identity, a noncanonical
identity/device encoding, an unknown policy version, a malformed field, or an
unsorted roster is refused. Reusing a device number for different identities is
valid.

The product owns these bytes. A later narrow core helper computes the
domain-separated roster commitment over this exact preimage; this decision does
not choose that primitive or add group cryptography.

## Considered

- Leave roster bytes implicit in product code.
- Use a raw concatenation of fields.
- Specify a length-framed preimage before adding a parser or commitment helper.

## Why

Membership, predecessor, and policy decisions are meaningful only when all
participants commit to one byte sequence. Full-tuple sorting prevents different
orders from describing the same roster. Framing and fixed widths let a parser
reject ambiguity before product policy or authority-channel validation. The
one-device experimental limit is explicit without treating device number as a
globally unique identifier.

## What would reopen this

A selected multi-device profile, a replacement product identity encoding, or a
core commitment helper with incompatible required input requires a versioned
successor format and migration plan. This record does not establish a group wire
format, an authority signature, a production group protocol, or a compatibility
claim.
