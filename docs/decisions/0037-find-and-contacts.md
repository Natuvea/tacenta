# 0037 — finding a user, and client-local contacts

## Decision

Two capabilities: resolving another user by name, and keeping a contact list.

- **`Client::find(username)`** resolves a username within the client's *own*
  tenant to a [`Contact`] (its addressable handle), or `None` if no such user
  is registered. The tenant is read from the client's own handle
  (`acme/alice` → `acme`), the target handle is `acme/<username>`, and the
  directory lookup answers exists-or-not. It is **exact resolution only** — no
  prefix search, no way to enumerate a tenant's membership.
- **`Contacts`** is a **client-local** list — added to on the device, never
  sent to the server. It serializes (`to_bytes` / `from_bytes`) so a caller
  can persist it. The server never learns who a user has added.

The echo bot gains an account mode (`EchoBot::sign_in`) so it runs under a
tenant handle (`acme/echo`) and is findable and addable like any other user;
the pre-account `EchoBot::connect` stays for the non-tenant case.

## Considered

- **Tenant search / browse** (prefix or substring, returning matches).
  Rejected: it lets any signed-in user enumerate the tenant's membership — a
  social-graph metadata leak. Exact resolution answers "does `acme/bob`
  exist?" without handing over the member list. If a deployment ever wants
  browse, it is an opt-in tenant setting, not the default.
- **Server-side contacts** (a stored contact graph per account, syncing across
  devices). More featureful, but it puts each user's social graph on the
  server — exactly the metadata an end-to-end-encrypted messenger should not
  hold. Rejected for the default; client-local keeps the graph on the device.
  Cross-device contact sync, if wanted, is later work done with encrypted
  client-owned blobs, not a plaintext server table.
- **A dedicated directory "resolve → devices" op.** Cleaner for multi-device
  (list a handle's devices), but there is no multi-device story yet — everyone
  provisions device 1 — so `find` resolves the primary device via the existing
  lookup and avoids a directory protocol change until multi-device earns it.

## Why

Discovery and contacts are where a messenger's metadata posture shows. Exact
resolution gives a user what they need — turn a name they already know into an
addressable handle — without turning the directory into a member scanner.
Client-local contacts keep the "who talks to whom" graph off the server, which
is the whole point of the E2EE stance: the server already cannot read message
content; it should not be handed the social graph either. Both choices are the
metadata-minimal option, and both can be relaxed deliberately (opt-in browse,
encrypted contact sync) rather than being open by default.

## What would reopen this

- **Multi-device.** When a user can have more than one device, `find` returns
  a handle's device set (via a directory resolve op), and messaging fans out
  across them.
- **Cross-device contact sync.** Keeping one contact list across a user's
  devices means an encrypted, client-owned blob the server stores opaquely —
  additive to the client-local list, not a move to a server-readable table.
- **Opt-in discoverability.** A tenant that wants a searchable directory turns
  it on explicitly; `find` stays exact-only for tenants that do not.
