# 0123 — bounded group genesis validation

## Decision

The canonical roster constructor and decoder reject an invalid genesis before
it can enter any receiver, outbox, or checkpoint. Revision zero must have an
all-zero predecessor digest, be open, list exactly the authority as its sole
member, and use the current policy. A later revision is the only way to admit
another member.

## Considered

- Leave genesis checks to the roster-view bootstrap path.
- Accept multi-member genesis in the product value and reject it later.
- Enforce the genesis profile in every canonical roster value.

## Why

Allowing an invalid r0 to be constructed lets tests or an integration skip the
authority-controlled admission transition. Requiring valid bytes at the codec
boundary keeps every later state machine on the same profile.

## What would reopen this

A future profile that intentionally supports a different bootstrap must use a
new policy version and its own canonical genesis rules.
