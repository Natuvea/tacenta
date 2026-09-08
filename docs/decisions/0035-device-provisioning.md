# 0035 — device provisioning: the account↔directory bridge

## Decision

A signed-in user binds a device's identity into the directory through a
dedicated **provisioning** endpoint. The client presents its session token
(decision record 0034), its device identity + prekey bundle, and a
proof-of-possession signature over the connection challenge; the server
validates the session, verifies possession, and registers the identity in the
directory under the account's handle.

Three shape decisions:

- **The handle is `"<tenant-username>/<username>"`** (e.g. `acme/alice`), and
  the **server derives it from the session** — the client never sends it. So a
  client can only provision a device under its own username, and the directory
  handle is human-readable and globally unique (tenant usernames are globally
  unique).
- **Provisioning is a server-level operation behind a `Provisioner` trait.**
  Binding an account to an identity needs three things no single crate owns —
  a valid session (accounts), proof of possession (crypto), and the directory
  write — so the transport defines the trait and the server implements it. The
  transport stays crypto- and account-free, and **the directory stays
  account-agnostic**: it still just applies trust-on-first-use to a
  handle→identity binding, knowing nothing about tenants or sessions (the 0033
  invariant).
- **Its own endpoint, with its own challenge.** Provisioning binds on its own
  port (`provisioning_port`, default 4723), issuing a per-connection challenge
  like the directory does. Signup/sign-in stay on the account endpoint, which
  needs no challenge; keeping them separate keeps each protocol to what it
  needs.

Trust-on-first-use still governs the binding: a second, different identity
presenting a valid session for the same handle is **rejected**, exactly as a
raw directory registration would be. Provisioning gates *who may attempt* a
binding; it does not override the directory's binding rule.

## Considered

- **Extend the directory's `Register` with a session token.** One endpoint,
  no new port. Rejected: it puts account state (sessions, tenancy) into the
  directory protocol and its transport, breaking the tenant-agnostic-core
  invariant (0033). The directory would have to reach into the accounts store,
  which is exactly the coupling the layering avoids.
- **Re-authenticate with the password at provision time** (no session token).
  Simpler — no session lifecycle. Rejected as the default now that sessions
  exist (0034): the token keeps the password to the one sign-in moment and
  gives every authenticated action one primitive. Re-auth stays available for
  a step that wants to force a fresh password check.
- **Let the client send the handle it wants.** Rejected outright — it is an
  impersonation hole. The handle must come from the authenticated session, not
  the request.
- **Fold provisioning onto the account endpoint** (add a challenge there).
  Workable, but it burdens the challenge-free signup/sign-in flow with a
  handshake it does not use. A separate endpoint keeps each protocol minimal.

## Why

This is the join that makes an account a messaging identity: after
provisioning, the directory resolves `acme/alice` to the device's key, and
everything downstream (relay auth, peer lookup, sessions) uses that binding
with no further account involvement — messaging authenticates with the
identity key, not the account. The account credential is needed only at this
one moment, to prove the registrant owns the username, which is exactly what
the session token attests. Keeping the directory account-agnostic means the
verified-core invariant holds and the trust-on-first-use rule is unchanged;
the gate sits *in front of* the binding, not inside it.

## What would reopen this

- **Session expiry / revocation** (0034) changes what "valid session" means at
  provision time, but not the shape here.
- **Multi-device UX.** Provisioning binds one `(handle, device)` at a time; a
  second device for the same user provisions under the same handle with a new
  device number. Listing or revoking a user's devices is account state this
  slice does not keep yet.
- **Rotation / recovery through the account.** Today a device rotates or
  recovers its directory binding with the key-continuity flows (0024 / 0025),
  independent of the account. Tying those to the account (re-key requires a
  session) would extend the provisioner beyond first-bind.
- **A durable store (0030).** Sessions and the account tables move to the
  database; the provisioner's reads (`validate_session`, `handle`) become
  queries.
