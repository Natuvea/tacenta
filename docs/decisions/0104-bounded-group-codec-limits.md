# 0104 — bounded group codec limits

## Decision

The bounded profile limits each canonical identity encoding to 256 bytes and
each device encoding to 64 bytes. A complete roster preimage may contain at
most 4,096 bytes; a complete application context may contain at most 2,048
bytes, including its 1,024-byte payload limit. Decoders reject an oversized
input before allocating a field from it, and constructors reject an oversized
member or complete value before it can enter group policy state.

These limits include the domain strings, framing, group ID, predecessor or
roster digest, authority and member bindings, and all context fields. They do
not introduce a production identity encoding or relax the eight-member,
one-device profile.

## Considered

- Bound only the payload and member count.
- Let callers impose storage limits after decoding.
- Apply explicit field and complete-value limits at each codec boundary.

## Why

Group control and deferred context state can otherwise retain arbitrarily large
opaque identity or device values despite the member and payload caps. Early
rejection makes the parsing, snapshot, and future-queue bounds concrete.

## What would reopen this

A production identity/device encoding or larger profile needs measured limits,
versioned codecs, and migration rules.
