# 0119 — bounded group control retains provider state

## Decision

An authenticated roster-control payload commits the provider state and effect
that decrypted it in the same combined snapshot as its roster disposition,
checkpoint, cancellation effects, and deferred-message revalidation. A failed
or unknown snapshot publication freezes the control operation and leaves the
live roster view and receiver unchanged.

The authenticated sender binding is checked against the pinned roster authority
before successor validation. A correctly encoded roster from another member or
route does not become control authority.

## Considered

- Commit roster state and pairwise provider state separately.
- Trust the authority identity carried in the roster payload.
- Commit one provider-bound control transition.

## Why

Control traffic can advance the same pairwise ratchet as application traffic.
Persisting the accepted epoch without that provider movement would make restart
retry the wrong authenticated ciphertext or lose a terminal provider effect.

## What would reopen this

A signed, sequenced production control channel may change authority evidence,
but it retains one durable boundary for provider state and membership effect.
