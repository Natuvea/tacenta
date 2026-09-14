# 0094 — bounded group application context

## Decision

The bounded group experiment carries its application context inside the
authenticated pairwise plaintext. It does not change pairwise associated data
and does not trust the relay's outer sender or group labels.

A version-one application context is length-framed in this order:

```text
"Tacenta Group Application v1" || lp(group_id) || u64be(revision)
|| lp(roster_digest) || lp(sender_identity) || lp(sender_device)
|| lp(recipient_identity) || lp(recipient_device) || u64be(logical_sequence)
|| lp(payload)
```

The sender and recipient bindings use the canonical forms from the accepted
roster. The receiver obtains the actual peer identity from the crypto-provider
outcome and requires it to equal the context sender binding. It also requires
the local recipient binding, group ID, revision, roster digest, and both member
bindings to match one accepted active roster. The payload bytes are immutable
under the logical sequence.

A changed group, revision, digest, sender, recipient, sequence, or payload is a
different context and must not reuse an accepted disposition. Pairwise success
with an invalid group context retains its provider state effect but creates no
membership or application effect. The product records its later durable
disposition before acknowledgement; this record does not implement that store.

## Considered

- Reuse the relay sender label as group identity evidence.
- Put group fields in unauthenticated routing metadata.
- Change pairwise associated data.
- Put the full context inside already authenticated plaintext.

## Why

The product can validate group policy only after pairwise authentication, while
the relay remains blind to the roster and application content. Requiring the
provider-authenticated peer to agree with the embedded sender prevents a relay
label or payload substitution from becoming identity evidence. Keeping the
pairwise associated-data contract unchanged limits this experiment to an
additive authenticated plaintext rule.

## What would reopen this

A core commitment helper, a canonical payload commitment representation, group
encryption, sealed sender, or a production multi-device profile requires a
versioned successor. This record does not define a group wire envelope, change
the relay, or make an end-to-end group security claim.
