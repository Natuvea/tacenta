# 0105 — bounded group logical intent record

> Bytes specified by 0149 (`spec/group-wire-formats.md`).
>
> Amended 2026-09-30 (by 0149, open point 1): the sender is written as one member
> entry, `lp(identity_bytes) || lp(device_bytes)`, two length-prefixed fields with
> no length around the pair, as the code has always written it. The layout below
> said `lp(sender_binding)`, a single field; it is corrected, and the code's form
> is the specified one.

## Decision

Before preparing any recipient ciphertext, the client durably records a
canonical logical-send intent in a `TCGI` outbox entry. Its preimage is:

```text
"Tacenta Group Logical Send v1" || lp(group_id) || u64be(revision)
|| sender_entry || u64be(sequence) || lp(roster_digest)
|| lp(payload) || u32be(recipient_count) || recipients
```

`lp(x)` is a four-byte big-endian length followed by exactly `x`. The sender and
each recipient are member entries, `lp(identity_bytes) || lp(device_bytes)`, with
no further length prefix. The recipient bindings are the same canonical full
identity/device ordering required by the bounded roster. The entry contains no
ciphertext or recipient progress; those are added by later prepared and handoff
records. The operation outbox records a candidate `GroupOutbox` and `TCGI` entry
in one snapshot before returning its logical send to any pairwise preparation
caller.

Exact duplicate immutable input returns the existing record without a new
snapshot generation. A reused logical ID with a changed roster digest, payload,
or recipient list conflicts. Failed or unknown publication leaves the live
outbox unchanged.

## Considered

- Allocate the logical ID in memory and persist only a first ciphertext.
- Serialize an implementation-specific debug form of a send.
- Commit a canonical logical intent before recipient preparation.

## Why

The pairwise result for each recipient is a consequence of one fixed group
intent. Publishing it first ensures retry/recovery cannot derive an altered
recipient set from a later roster.

## What would reopen this

A production group wire format or multi-device profile needs a successor
intent grammar and corresponding recovery codec.
