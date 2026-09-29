# 0116 — group envelope classification at the client boundary

> Corrected 2026-09-29: an earlier text called the class authenticated.

## Decision

The client preserves the relay envelope class alongside each decrypted inbound
payload. Direct messages, group payloads, and receipts are distinct
application classes. The class is the relay's outer label: it is not bound into
the ciphertext or the pairwise associated data (decision 0094 keeps that
unchanged), so a relay can relabel a direct message as group traffic or the
reverse. It selects a parser and is not evidence of origin. A future group
coordinator consumes only `group`-classified plaintext before applying roster
and recipient validation; it must never infer group semantics from arbitrary
direct-message bytes, and the group payload carries its own domain, tag and
authenticated context.

The Rust client and its FFI/WASM projections expose the same class; the
TypeScript head does not surface it yet. Existing
direct sends continue to create the `direct` class.

## Considered

- Treat every decrypted payload as a direct message.
- Guess group content from its plaintext prefix.
- Preserve the relay envelope class through each client projection.

## Why

The outer class selects the application parser before group policy operates.
Keeping it avoids a direct payload accidentally entering the group state
machine and makes the eventual live group dispatch visible to SDK users.

## What would reopen this

A versioned multiplexed application envelope can replace these classes only if
it preserves an unambiguous authenticated dispatch rule.
