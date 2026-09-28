# 0116 — group envelope classification at the client boundary

> Corrected 2026-09-29: an earlier text called the class authenticated.

## Decision

The client preserves the relay envelope class alongside each decrypted inbound
payload. Direct messages, group payloads, and receipts are distinct routing
classes. The group coordinator (`GroupClient::receive`, 0131) hands only
`group`-classified plaintext to the group parsers; it never infers group
semantics from the bytes of a direct message.

**The class is not authenticated.** The sender chooses it and the relay carries
it in the outer envelope; the pairwise associated data does not cover it (0094
leaves that data unchanged), so a relay can relabel a direct envelope as group
or a group envelope as direct without failing any check. The earlier wording of
this record and the `MessageKind` documentation called it authenticated; that
was wrong.

**Consequence, stated exactly.** Misrouting and availability, not integrity. A
direct message relabelled `group` reaches the group parser, fails its canonical
decoding and becomes a terminal `malformed` disposition: the coordinator
consumes it and it is never shown as a direct message. A group payload
relabelled `direct` is delivered to the application as a direct message and
changes no group state. No group state changes on the label alone: every
transition requires the inner payload to decode under its own domain and tag and
requires the pairwise-authenticated peer to be the sender or authority the
payload names. A relabelled envelope therefore cannot cause a group state change
that the payload's own authentication would not have permitted. That the
coordinator consumes only group-classified plaintext is a caller convention,
implemented in `GroupClient::receive`; nothing in the envelope enforces it.

The Rust client and its FFI/WASM projections expose the same class, documented
as a routing label; the TypeScript head does not surface it yet. Existing
direct sends continue to create the `direct` class.

## Considered

- Treat every decrypted payload as a direct message.
- Guess group content from its plaintext prefix.
- Preserve the relay envelope class through each client projection.

## Why

The outer class selects the application parser before group policy operates.
Keeping it avoids a direct payload accidentally entering the group state
machine and makes the live group dispatch visible to SDK users. It is honest
only if it is described as a hint the payload's own authentication does not
depend on.

## What would reopen this

A versioned multiplexed application envelope can replace these classes only if
it preserves an unambiguous authenticated dispatch rule. Binding the class into
the authenticated plaintext or the pairwise associated data would remove the
relabelling consequence above, and needs a core change and a wire profile.
