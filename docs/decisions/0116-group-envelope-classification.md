# 0116 — group envelope classification at the client boundary

## Decision

The client preserves the authenticated relay envelope class alongside each
decrypted inbound payload. Direct messages, group payloads, and receipts are
distinct application classes. A future group coordinator consumes only
`group`-classified plaintext before applying roster and recipient validation;
it must never infer group semantics from arbitrary direct-message bytes.

The Rust client and its FFI/WASM projections expose the same class. Existing
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
