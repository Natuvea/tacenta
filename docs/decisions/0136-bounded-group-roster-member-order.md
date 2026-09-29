# 0136 — bounded group roster member order

> Clarifies 0092. Amended by 0135.

## Decision

A canonical roster lists its members in strictly ascending order of the pair
`(identity_bytes, device_bytes)`. The two fields are compared separately: the
identity bytes first, as unsigned byte strings under ordinary lexicographic
order (a proper prefix sorts before every extension of it), and the device
bytes only when the identity bytes are equal. The order is never taken over the
concatenation `identity_bytes || device_bytes`, and never over the
length-framed encoding of an entry.

The bounded profile also requires every identity to appear once, so the device
bytes only ever break a tie that the one-device rule then refuses. In a
valid roster the order is therefore the strictly ascending order of the
identity bytes alone. The same order applies to the recipient list of a
logical send and to its recovered intent.

The wording of decision 0092 ("the full `identity_bytes || device_bytes`
tuple") is read as this pair, as the design notes for this profile also put
it ("full tuple sorting ... not raw concatenation"; those notes are not in this
repository, and this record does not rest on them). Before this record the code compared the
concatenation. That order disagrees with the pair order exactly when one
identity is a proper prefix of another: `("a", [0xff])` sorts before
`("ab", [])` as a pair but after it as a concatenation, and `("a", "bc")` and
`("ab", "c")` concatenate to the same bytes, so no order of them was accepted.
The roster preimage bytes do not change; only which member lists are accepted
as canonical changes, and only for identities that are prefixes of one
another. Nothing carrying either order has been released.

## Core boundary (the five questions)

1. **Does this keep the trusted core small?** Yes. Nothing in tacenta-core
   changes. It commits to the opaque preimage bytes and never sorts members.
2. **Is the behaviour owned by a written specification?** Yes: this record and
   0092 own it, and the group tests pin it with the two prefix cases above.
   There are no committed byte vectors for the roster preimage yet.
3. **Can the security claim be reproduced?** Yes, by
   `cargo test -p tacenta-group --test group_fixes`. No security claim rests on
   the order; it is a canonicality rule.
4. **Does it preserve wire compatibility with a named profile?** No named
   profile carries the group roster. The bounded experiment is unreleased, so
   no persisted roster is migrated.
5. **Is this protocol functionality, or product coupling trying to enter the
   core?** Product policy. The core's roster commitment stays a hash of bytes
   the product supplies.

## Considered

- Keep the concatenation order and reword 0092 and the design notes to match.
- Sort by the length-framed encoding of each entry.
- Sort by identity bytes alone and treat the device as a check, not a key.

## Why

Concatenation is ambiguous: two distinct members can produce the same sort key,
and it lets a device byte decide the order of two different identities. Each
of those is the failure that a tuple rule exists to prevent, and
it is latent only while identities are fixed-width keys. Decision 0104 allows
256-byte identities. The framed encoding would order by length first, which is
neither what the ADR text says nor what the client's own fixtures already do:
they sort by identity bytes and then device bytes. Sorting by identity alone is
equivalent for valid rosters, but the pair keeps the rule stated for the full
binding and stays correct if the one-device rule is later relaxed.

## What would reopen this

A multi-device profile, a variable-width or non-byte identity encoding, or a
published byte vector that fixes a different order needs a versioned roster
format and a migration rule.

## Amendment (0135)

`Member::canonical_cmp` is public. The client sorts rosters and recipient
lists with it in production code instead of a copy of the rule, so the two
cannot drift.
