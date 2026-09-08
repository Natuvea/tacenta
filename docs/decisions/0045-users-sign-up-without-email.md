# 0045 — users sign up without email

## Decision

A **user** signs up with a username and password only — no email. Email stays on
the **tenant** (the customer organisation), which still signs up with username,
email, and password. This supersedes the user-email part of decision record
0033.

Consequences:

- A user is identified within its tenant by `username` alone; `(tenant_id,
  username)` remains the primary key and the only uniqueness constraint. There is
  no per-tenant user-email uniqueness any more.
- Sign-in is by **username** plus password. The prior "username or email"
  resolution is gone (the account service no longer knows a user's email —
  there isn't one).
- `SignupError::EmailTaken` remains, raised only by tenant signup.

## Verification

`cargo test` across `tacenta-accounts` (in-memory and, against a real Postgres,
`tests/pg.rs`), `tacenta-transport`, `tacenta-client`, `tacenta-ffi`,
`tacenta-echo`, and `tacenta-server` passes with the email dropped from the user
paths. Migration `0003_drop_user_email.sql` drops the `users.email` column and
the `users_tenant_email_key` constraint that depended on it; the Postgres tests
exercise the new schema.

## Considered

- **Keep an optional user email.** Rejected: an optional-but-unused field is
  dead weight and an extra thing to normalise, validate, and reason about in the
  timing/enumeration analysis. Users are addressed by handle; email added nothing
  for them. It can return additively later (like 2FA / passkeys) if a concrete
  need appears — a nullable column and an optional field, no data migration.
- **Drop email from tenants too.** Rejected: a tenant is a billing/contact
  entity for which an email is the natural contact and recovery channel; that is
  a different role from an in-tenant messaging user.

## What would reopen this

- **A concrete need for user email** (recovery, notifications). It returns as an
  optional, additive field — not a required signup input — so this decision does
  not preclude it.
- **The account wire protocol.** `AccountRequest::SignUpUser` dropped its `email`
  field (tag 2); any external client encoding that request must drop it too. The
  format is not yet externally versioned (pre-alpha).
