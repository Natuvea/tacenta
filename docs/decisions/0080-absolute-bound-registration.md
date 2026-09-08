# 0080 — the absolute-bound registration layer: account-gated registration (layer 2)

## The residual layer 1 leaves

Layer 1 (decision 0079) throttles *new* handle registrations per source IP.
Its stated residual: an attacker with many source addresses defeats a per-source
throttle, so layer 1 makes mass registration *costly*, not *impossible*. It is not
a hard cap on the handle count. A deployment that needs a genuine absolute bound —
"no more than the operator has admitted" — needs a gate that does not depend on the
source address.

## The two candidate gates

Both bind the handle count to an operator-controlled scarce credential rather than
to the source IP:

- **Invite tokens.** A new handle requires presenting a valid, operator-minted
  invite. Hard cap = tokens issued. Self-contained, but a *generic* single-use
  token (the invitee picks their own handle) needs its consumption persisted across
  restarts to stay a hard cap — otherwise a token reused after a restart binds a
  second handle. That means a new persisted token store, an issuance path, and
  restart-safe consumption: real new surface.
- **Account-gated registration.** Reuse what the product already has. Account
  handles (`tenant/user`) are bound only through **authenticated** provisioning
  (`AccountProvisioner`: a validated session + possession), which is already
  throttled at the gateway and costed by argon2. The unauthenticated raw-handle
  `Register` path is the cheap one. Closing raw self-registration forces every
  handle through the authenticated account path, and the handle count is then
  bounded by the account hierarchy.

## Decision

**Ship account-gating as layer 2**, because it delivers an absolute bound by
reusing authenticated machinery that already exists, at a fraction of the surface
and risk of a from-scratch token store. Invite tokens are recorded here as the
**complementary** option for a deployment that has no account layer and wants
generic invites; that is a separate increment (persisted single-use token store +
issuance), not built now.

A `RegistrationPolicy` selects the mode on the directory server:

- **`Open`** (default) — anyone may self-register a new raw handle, subject to the
  layer-1 per-source throttle. Unchanged behaviour.
- **`AccountsOnly`** — a *new* raw-handle `Register` on the unauthenticated
  directory path is refused (`DirResponse::RegistrationClosed`). Handles are
  obtained only through authenticated account provisioning. **Re-confirms of an
  already-bound handle still succeed**, so a returning client is never locked out,
  and account provisioning (`AccountProvisioner::provision`, which calls
  `Directory::register` directly, not through this path) is unaffected.

Selected by config: `TACENTA_REGISTRATION_POLICY=accounts-only` (default `open`),
threaded through `Server::bind`.

## The residual, stated plainly

Account-gating closes the *unauthenticated raw* path absolutely, but the bound it
then rests on is the **account-creation policy**. If `sign_up_tenant` /
`sign_up_user` are open to the world, the handle count is bounded only by the
gateway signup throttle — which is per-IP, i.e. the same distributed-source
residual one layer up. **A true hard bound therefore requires the operator to
control account creation** — gate tenant creation to admins (or disable public
`sign_up_tenant` in production), so users exist only inside operator-admitted
tenants. That is a deployment/policy setting, not a code default, and is the honest
edge of this layer: `AccountsOnly` + operator-controlled tenants is the absolute
bound; `AccountsOnly` + open tenant signup just relocates the per-source throttle.

## Status

Layer 2 (account-gating via `RegistrationPolicy::AccountsOnly`) is the increment
this record covers. Generic persisted invite tokens — for account-less deployments
that want them — are the deferred complementary layer.
