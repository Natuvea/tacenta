# 0107 — bounded group provider binding

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
`TCGM` inbox record with the opaque provider state and provider state effect.
It creates no application event, but its required state transition is retained
before an ACK may cross it.

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
