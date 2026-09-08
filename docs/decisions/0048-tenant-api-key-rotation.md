# 0048 — tenant API-key rotation

## Decision

A tenant can rotate its API key without ever having the old one, by
re-authenticating with its **email/username + password** (the credential it set
at signup, argon2id-hashed). Rotation is modelled as
multi-key management, not a single destructive swap, because the `api_keys`
table already allows several keys per tenant:

- `POST /v1/tenants/keys/create` — mint an additional key (returned once).
- `POST /v1/tenants/keys/list` — list keys by non-secret prefix, never the key.
- `POST /v1/tenants/keys/revoke` — revoke a key by prefix; it stops resolving
  immediately.

Each call carries `{ email, password }` and is rate-limited per IP. Bad
credentials return a coarse `401 invalid_credentials` that never distinguishes
"no such tenant" from "wrong password".

This serves both triggers:

- **Leaked key.** The tenant can see the leaked key (it is public), match its
  prefix, and revoke that one. For zero downtime they create a new key and
  deploy it first, then revoke the leaked one.
- **Forgot key.** The old key is not required — the password mints a new one.

## Key identity: a stored prefix

A key row of `(key_hash, tenant_id)` alone gives a tenant nothing to tell two
keys apart. Migration `0004` adds `key_prefix` (the first 12 characters,
`tct_` + eight hex — 32 of the key's 256 bits, non-secret), an optional `label`,
and `created_at`. The full key is still never stored; only its SHA-256 digest is.
Keys created before the migration have a null prefix and cannot be revoked by
prefix.

## Authentication: password, not email

Password auth needs no new infrastructure — `authenticate_tenant` already exists
in both the in-memory and Postgres stores. An email-based flow (magic link /
code) would be more robust when the password is also forgotten, but Tacenta has
no email sending yet, and the signup email is unverified, so an email anchor
could not be trusted without first building verification. Password now; email
reset later, when email exists anyway.

## No lock-out guard

Revoking the last key is allowed. A tenant with its password can always mint a
new key, so there is nothing to lock itself out of; a "cannot delete last key"
rule would only get in the way during an incident.

## Considered

- **Rotate with the old key (present old → get new).** Rejected as the primary
  path: it fails the forgot-key case, and a leaked key could rotate itself.
  Viable later as a convenience for automated rotation, with the caveat noted.
- **Single destructive rotate (revoke all + issue one).** Simpler, but an
  immediate cutover breaks the tenant's running app until redeploy. The schema
  already supports multi-key, so the zero-downtime model costs little more and
  is strictly better.
- **A tenant session first.** The right eventual home (a tenant signs in once,
  then manages keys). Deferred; re-authing per call ships the capability now
  without building session storage.

## What would reopen this

- Adding email sending — then a password-reset (and email-verified recovery)
  flow becomes possible and should be added alongside.
- A tenant session (the "effectively signed in" surface) — the key
  endpoints move behind it, and per-call credentials become a session token.
- A tenant needing many keys with independent scopes or expiries — the flat
  `(prefix, label, created_at)` model would grow scopes and `expires_at`.
