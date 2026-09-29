# 0107 — bounded group provider binding

> Amended by 0133 (the collections it retains are bounded).

> Status (2026-09-29, after 0131): `GroupClient::receive` decrypts with
> `decrypt_with_outcome` and takes the authenticated peer and the state effect
> from it; no caller supplies either. The plain `Client::receive` still decrypts
> with `party.decrypt`, which discards the outcome. `GroupReceiveInput` is not
> sealed: its fields are `pub(crate)`, so review, not the compiler, keeps other
> code from building one by hand.

## Decision

The client group adapter derives an authenticated `Member` only from the
provider outcome and the crypto-layer peer address. Its identity bytes are the
provider's `authenticated_peer`; its device bytes are the exact one-byte crypto
device ID. Relay routing labels never supply either field. This matches the
bounded profile's one-device representation and the existing client rule that
relay device IDs must fit the crypto layer's `u8` address.

After pairwise decryption, the adapter decodes the bounded application context
and passes that derived member to the durable receiver coordinator. A malformed
group plaintext creates a terminal `Malformed` disposition recorded in a
`TCGM` inbox record with the provider state effect, the plaintext length and
its payload commitment (41 bytes with the tag; the plaintext itself is not
retained, 0133),
committed together with the provider state. It creates no application event, but
its required state transition is retained before an ACK may cross it.

## Considered

- Use the relay sender address as group identity evidence.
- Infer a device binding from arbitrary product bytes.
- Bind the provider identity and crypto device explicitly, and durably record
  malformed authenticated payloads.

## Why

Pairwise authentication establishes the peer identity while relay attribution
only routes mail. A malformed group payload must not turn a required crypto
state transition into an unacknowledged poison item.

## What would reopen this

A multi-device profile or different core address representation requires a
versioned member-binding grammar and migration rule.

## Amendment (0131)

The derivation above is what the live path does: `GroupClient::receive` builds
the member from the outcome of `decrypt_with_outcome` and the crypto device of
the routed address. Before 0131 every live trace supplied the identity and the
state effect by hand, so this record described a binding that no production code
performed.
