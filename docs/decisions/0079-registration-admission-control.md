# 0079 — registration admission control bounds the handle count

## The problem

The relay bounds memory at every level — per-envelope, per-device (`MAX_QUEUE_BYTES`), per-user
(`MAX_USER_BYTES`), and the whole node (`MAX_TOTAL_BYTES`). But those caps bound
*memory*, not *fairness*: at the node ceiling refusal is global backpressure, so
on an **open** self-service deployment a party who can register recipient handles
cheaply can register many, fill them, and crowd out everyone's availability up to
the ceiling. The relay already refuses sends to *unregistered* addresses, so the
attacker must register recipients — which makes "how cheap is registering a
handle?" the load-bearing question.

## Why relay-level fairness is not the fix

The tempting answer — divide the ceiling fairly per principal (reservations,
weighted shedding) — does not hold against this adversary. Per-principal fairness
splits resources among principals; if a handle is free, the attacker just makes
more principals, each collecting its fair share, and still crowds out real users.
**Fairness only bites once the number of principals is bounded**, and bounding the
principal count is admission control, not a queue policy. So the fix must live at
registration, not in the relay. (Relay fairness is worth building only *on top of*
this, for a bounded-tenant model — never as a substitute.)

## Decision

**Bound the rate of new handle registrations per source, at the directory.** The
first, lowest-friction, privacy-compatible layer is a per-IP sliding-window
throttle on the directory `Register` path — the same shape as the gateway's proven
signup limiter (`tacenta-gateway::ratelimit`), including its map-growth defence
(evict callers who can no longer be blocked, then cap the map). It is chosen over
the alternatives deliberately:

- **not invite-gating** — it caps organic growth and needs an issuance system;
- **not proof-of-work** — weak against resourced attackers, and a battery/CPU tax
  on honest mobile clients;
- **not registration behind a full account** — raw first-come handles
  (`Client::connect`) are an intentional product feature (0019); gating them
  changes the model. Account-namespaced handles already pass through the argon2 +
  tenant gate and the per-IP gateway signup throttle.

## What is throttled, and what is not

Only a **new** binding is throttled — `Directory::register` returning
`Registration::Registered` (a handle with no existing entry). Deliberately
excluded:

- **Re-confirms** (`Registration::Refreshed`, same key, new bundle) — a returning
  client reconnecting must never be throttled out of its own handle, so the limiter
  is consulted *only* when no entry exists for the device.
- **TOFU rejects** (`Registration::Rejected`, a key-change on an existing handle) —
  already refused by trust-on-first-use; not a new handle, not rate-limited.

Enforcement holds the directory lock to decide newness, checks the limiter only for
a new handle, and records only a registration that actually created a binding — so
a refused attempt does not push the window forward, and a re-confirm costs nothing.

## The wire and the surfaces

- A new `DirResponse::RateLimited` (its own tag), returned when a new-handle
  registration is over the ceiling. Distinct from `PossessionFailed` /
  `ReservedHandle` on purpose — a client must be able to tell "retry later" from
  "you may not have this handle." The possession check runs *before* the limiter,
  so a caller who cannot prove the key learns nothing about the throttle.
- The directory accept loops thread the peer IP into the request handler; the
  directory sees the client's socket address.
- Config: `TACENTA_REGISTRATION_MAX_PER_HOUR` (default a low ceiling; legitimate
  registration is rare per source), unset uses the default. The window is one hour,
  matching the gateway limiter.

## The residual, stated plainly

**Per-IP throttling is defeated by an attacker with many IPs** (a botnet, a cloud
range, IPv6 rotation). It raises the cost of mass registration from free to
"one source per N handles per hour," which is a real and worthwhile bound, but it
is **not an absolute cap on the handle count** and therefore not a complete
defence against many-source registration. A deployment that needs a hard bound must add a stronger gate on top —
invite-only registration, or account-gated handles — and that choice is a
deployment/product decision, recorded here as the next layer rather than implied to
be done. This is the honest scope: this layer makes cheap mass registration
costly, not impossible, and the public claim stays "memory-bounded, with
per-source registration throttling."

## Status

Layer 1 (per-IP directory throttle) is the increment this record covers. The
stronger absolute-bound gate (invite / account-gated) is deferred to a deployment
that requires it.
