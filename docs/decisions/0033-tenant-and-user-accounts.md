# 0033 — tenant and user accounts: username, email, password

> Superseded in part by 0045.

## Decision

Tacenta gains a control-plane identity layer, `tacenta-accounts`. A **tenant**
is a customer organisation with an API key that isolates its users; a **user**
is an account within a tenant. Both sign up with a **unique username, email,
and password**:

- **The username is the messaging handle.** A user's username is how peers
  address them, not just a login credential — it is the identity the directory
  binds. Email and password are for signing in.
- **Uniqueness is global for tenants, per-tenant for users.** Two different
  tenants can each have a user `alice` with the same email; within one tenant
  both are unique. Tenant usernames and emails are unique across the platform.
- **Passwords are hashed with argon2id**, never stored or compared in the
  clear. Uniqueness is enforced on username and email only — never on the
  password (a unique-password check is a security anti-pattern; it reveals that
  a password is already in use).
- **2FA and passkeys are a later, additive layer.** The credential is a
  password today; the model grows to add factors without reshaping accounts.

The verified protocol core (`tacenta-wire` / `state` / `directory` / `relay`)
stays tenant-agnostic. Tenancy lives entirely in this crate, which maps a
`(tenant, username)` to the handle the directory binds. The store is in-memory,
matching the current server posture; it is the natural first consumer of the
durable store (decision record 0030).

## Considered

- **Thread tenancy through the whole stack** (a tenant id on `DeviceAddr`, the
  directory and relay partitioned by tenant). Rejected: it would put tenancy
  inside the Lean-verified zone, for no gain the control-plane mapping does not
  already give. Keeping the core tenant-agnostic preserves the forward-compat
  contract — an earlier verified slice does not change to accommodate a later
  control-plane one.
- **OTP / email-code or passkey-first signup.** Rejected for now by choice: username/email/password is the requested baseline,
  simpler to reason about, and passkeys/2FA layer on top rather than being the
  entry requirement.
- **Global uniqueness for users.** Rejected: it couples tenants (one tenant's
  user list constrains another's) and breaks the "same human, two tenants"
  case. Per-tenant uniqueness is the isolation the tenant concept exists for.
- **Store the API key in the clear.** Rejected: the key is a bearer credential,
  so the store keeps only its SHA-256 and returns the plaintext once at
  creation. High-entropy tokens do not need a slow hash; a fast digest keyed
  lookup is right.

## Why

The tenant concept — a customer org with an API key isolating its users —
pairs with an ordinary username/email/password signup, which is the requested
baseline and what passkeys/2FA extend later. Making the username the handle unifies "who you are to peers" with
"who you sign in as", so the account layer produces the directory identity
directly rather than carrying a second address. Per-tenant uniqueness is the
whole point of tenants.

Two security choices are deliberate and worth stating, because green here is
less than it looks: authentication errors are **coarse** (`InvalidCredentials`
never says whether the account exists), and a missing account is still run
through a **dummy argon2 verify**, so neither the error nor the response time
reveals which usernames or emails are registered. Password length is bounded
above as well as below, so a huge input cannot turn argon2 into a
denial-of-service lever.

The store is in-memory because that is the current server posture; nothing
about the model assumes it. When the durable store (0030) lands, these tables —
tenants, users, the uniqueness indexes, the API-key digests — are its first and
most obviously relational tenant.

## What would reopen this

- **2FA and passkeys.** The credential model gains factors; accounts do not
  change shape, which is the test of whether this decision held.
- **Federation or cross-tenant users.** A single human account spanning tenants
  would revisit the per-tenant uniqueness boundary.
- **The durable store lands.** The in-memory `Accounts` moves behind the same
  Postgres store as the directory and relay (0030), with the uniqueness indexes
  becoming database constraints.
- **Wiring into the request path.** This slice is the model and its rules;
  authenticating a device provision or an SDK call against a tenant API key,
  and binding a signed-up username into the directory, is the next slice.
