# 0034 — session tokens on sign-in

## Decision

A successful user sign-in issues a **session token**: `Accounts::sign_in`
authenticates (as `authenticate_user` does) and, on success, mints an opaque
token bound to that user, returning it once. `Accounts::validate_session`
resolves a token back to its `(tenant, username)`. The account transport's
`SignedIn` response carries the token alongside the handle.

The token is a high-entropy random string (`ses_…`); the store keeps only its
SHA-256, so the returned plaintext is the only copy — the same treatment as an
API key. Sessions do not expire yet.

The token exists to authorise the **device-provisioning** step that comes
next: a client signs in once, then presents the token to bind its device's
identity into the directory under its username, rather than re-sending the
password on that call.

## Considered

- **Re-authenticate on every account action** (send the password again at
  provision time). Simpler — no session state — and defensible because
  provisioning is rare and ongoing messaging authenticates with the device's
  identity key, not the account. Rejected as the primary mechanism: a session
  is the standard shape, keeps the password to the one sign-in moment, and
  gives later authenticated actions (revoke, rotate credentials, multiple
  device provisions) a uniform primitive. Re-auth remains available for a
  step that wants to force a fresh password check.
- **A stateless signed token (JWT / MAC).** No server-side session table, and
  it scales across processes without shared state. Rejected for now: it needs
  a signing key and a rotation story, revocation becomes a denylist (the thing
  a stateful table gives for free), and there is a single in-memory store
  today anyway. Revisit when the store is durable and multi-process (0030) —
  at which point a stateless token or a shared session table is the fork.
- **Return no token, just success.** Rejected: it
  proves the password over the wire but hands back nothing to act with, so the
  next authenticated call would have to re-authenticate regardless.

## Why

Gating directory registration on an account needs an authorisation the
registration step can check. A session token is that authorisation, minted at
the one moment the password is verified and carried forward without re-sending
it. Keeping the token opaque and server-side (hash-at-rest, table lookup)
makes revocation and expiry a local change to the store rather than a
cryptographic protocol, which is the right trade while the store is a single
in-memory map.

## What would reopen this

- **Expiry and revocation.** Sessions live forever today and vanish on
  restart (in-memory). A real deployment needs a TTL and an explicit revoke;
  both are additions to the session table, not reshapes of this decision.
- **A durable, multi-process store (0030).** Shared session state across
  processes forces the choice this decision deferred: a shared session table
  in the database, or a stateless signed token.
- **The provisioning step lands.** It is the first consumer of
  `validate_session`; if it turns out to want more in the session than
  `(tenant, username)` (say, the device it was issued for), the session value
  grows.
