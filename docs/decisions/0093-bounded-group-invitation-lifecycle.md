# 0093 — bounded group invitation lifecycle

## Decision

The bounded group experiment records an invitation as a product policy record
with: a 16-byte invitation ID, the 16-byte group ID, the exact target
identity/device binding, the source revision and roster digest, policy version
one, and an unsigned 64-bit logical expiry. The authority creates it only for
a non-member target under its directly authenticated pairwise channel.

At logical time `now`, an invitation is valid exactly when `now < expires_at`.
A target may change a valid pending invitation to
`accepted_pending_admission`; that state grants no membership or application
permission. Only the authority's accepted successor roster revision changes it
to `admitted(revision)`. The authority may change a pending or accepted
invitation to `revoked`. Revocation and expiry win over admission.

The same invitation ID is idempotent only when every immutable field and the
requested disposition match the committed record; it returns that record's
current disposition. Reusing the ID with any changed field is a conflict. A
wrong target/device, stale source revision/digest, unknown policy version,
malformed fixed-width field, revoked, expired, or conflicting record is refused
without changing membership.

## Considered

- Treat acceptance as membership.
- Let the recipient's clock decide expiry.
- Make duplicates silently overwrite the stored invitation.
- Keep a durable authority-side record and a pending recipient-side record.

## Why

A direct pairwise channel authenticates the authority message but cannot turn
an invitation into group membership. A separate pending state makes the
authority's admission revision the one activation point. Logical time gives
model fixtures a deterministic strict boundary; restart and wall-clock mapping
remain an explicit later storage contract. Immutable IDs make retries safe
without allowing target or bootstrap substitution.

## What would reopen this

A multi-device, delegated-authority, policy-upgrade, or real-time expiry
profile requires a new versioned lifecycle. This record does not specify the
invitation wire bytes, a detached signature, an automatic history transfer, or
an application-level delivery receipt.
