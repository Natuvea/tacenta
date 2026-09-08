# Threat model

What Tacenta defends, against whom, and — as important — what it does **not**
defend. Written to be falsifiable: each guarantee names the mechanism behind it
and the assumption it rests on, so a reviewer can check the claim rather than
take it on faith. Paired with [the verification TCB](verification-tcb.md) (what
the proofs assume) and [claims.md](claims.md) (proven vs tested vs assumed).

## System in one paragraph

Clients encrypt end to end with an owned, clean-room implementation of the
Signal protocol designs (X3DH/PQXDH key agreement, Double Ratchet, ML-KEM-1024
post-quantum), provided by the pinned tacenta-core dependency (decision 0075).
The server never holds a decryption key. The server is five cryptographically-blind services: a **directory**
(public identity keys + prekey bundles), a **relay** (routes opaque ciphertext,
store-and-forward), an **account** service (tenant/user signup and sign-in),
**provisioning** (binds a signed-in user's device identity into the directory
under its handle), and a **gateway** (the public control plane the website
talks to: tenant signup and API-key management, `tacenta-gateway`). Message *content* is protected by the E2EE regardless of the
server; the server's honesty matters only for *metadata*, *availability*, and
*first-contact key authenticity*.

## Adversaries and what each gets

### 1. Network attacker (passive or active on the wire)

- **Content:** protected. Messages are end-to-end encrypted; the wire also runs
  over TLS (decision record 0023) as defence in depth. A passive attacker sees
  ciphertext and its metadata; an active attacker cannot forge a message (relay
  and directory operations are authenticated by an identity-key signature over a
  fresh per-connection challenge).
- **Metadata:** exposed — see "What the server sees". TLS hides it from a
  network observer but not from the server itself.
- **Availability:** an active attacker can drop or delay. Not defended (no
  anonymity/availability network is in scope). The relay's byte budgets bound
  *memory* — a node cannot be driven to OOM (`MAX_ENVELOPE_BYTES`,
  `MAX_QUEUE_BYTES`, `MAX_USER_BYTES`, and the whole-node `MAX_TOTAL_BYTES`) — but
  they are **memory-bounding, not fairness-guaranteeing**: at the node ceiling
  refusal is global backpressure, so on an *open* self-service deployment a party
  who can register many recipient handles cheaply can still degrade availability
  for others up to that ceiling. Bounding *that* is admission control at
  registration, not relay fairness: the directory throttles new handle
  registrations per source, and `TACENTA_REGISTRATION_POLICY=accounts-only`
  closes the unauthenticated raw-handle path so every handle passes through
  account provisioning (see decisions 0079 and 0080). A per-source throttle is
  defeated by an attacker with many addresses, so a public open-registration
  deployment chooses its policy: the throttle alone, or account-gated handles
  under operator-controlled account creation. A tenant-limited or invite-gated
  deployment, where the count of registerable handles is externally bounded, is
  not exposed to this.

### 2. Honest-but-curious or malicious server

- **Cannot read message content** — the relay routes ciphertext it has no key
  for; forward secrecy (Double Ratchet) means compromising the server today does
  not decrypt yesterday's messages. **One exception, and it is not a small
  one:** if a peer's one-time prekeys are exhausted when a bundle is fetched,
  the resulting session's *initial* message has no forward secrecy against a
  later compromise of that peer's long-lived signed prekey — the one-time key
  is what makes the first message unrecoverable, and there is none. Decision
  record 0050 states this and declines to hide it behind an unqualified claim.
  Every message after the first ratchet step is unaffected.
- **Cannot recover passwords, API keys, or session tokens** — passwords are
  argon2id hashes; API keys and session tokens are stored only as their SHA-256. The
  signup gateway throttles by the **rightmost** `x-forwarded-for` element, the
  one the nearest proxy appended; reading the leftmost let a caller choose its
  own throttle bucket per request, because the nearest proxy appends. A
  sign-in flood against one tenant (200 failures a minute) is refused before the
  credential check runs, which **suspends the anti-enumeration dummy verify for
  the duration**: two correct defences otherwise compose into a memory lever,
  because every attempt costs 19 MiB and a caller cycling identifiers never
  trips the per-identifier ceiling. Enumeration resistance is traded for
  availability, and only while the flood lasts.
- **Can see metadata** and **can deny service** (see below).
- **First-contact key authenticity is the real limit.** The directory serves
  identity keys and prekey bundles. A malicious directory could serve an
  attacker's key on a peer's *first* contact (a classic trust-on-first-use MITM).
  Tacenta mitigates but does not eliminate this: the binding is trust-on-first-
  use, later key changes are detectable via a safety-number comparison, and an
  authorized key change goes through key-continuity rotation (0024). Closing the
  first-contact gap entirely requires **out-of-band safety-number verification**
  between peers — the standard Signal-family answer, and the user's
  responsibility, not the server's.

- **Replay is bounded, not eliminated.** The relay can re-deliver a captured
  ciphertext. An established session rejects it: the ratchet consumes a message
  key exactly once, so a duplicate decrypts to nothing. An *initial* message is
  the harder case, and decision record 0071 states the rule and its limit — a
  one-time prekey is consumed exactly once, which stops the replay, but only for
  as long as one-time prekeys last. Past exhaustion the bundle falls back to a
  reusable last-resort key, and a replayed initial message opens a fresh
  duplicate session each time. No content leaks either way; the cost is
  unbounded session creation from one captured message.

### 3. Malicious tenant, or cross-tenant access

- Tenants are isolated: a tenant's API key scopes every account operation to
  that tenant, user uniqueness is per-tenant, and a user's messaging handle is
  tenant-namespaced (`acme/alice`). One tenant cannot enumerate, authenticate,
  or provision another tenant's users. The uniqueness boundary is enforced in
  the store — in Postgres, by database constraints.

### 4. Account attacker (signup / sign-in)

- Passwords are hashed with **argon2id at m=19 MiB, t=2, p=1**, pinned in
  `crates/tacenta-accounts/src/lib.rs` and held there by a test, so a
  dependency bump cannot move the cost silently. Raising it
  later needs re-hashing on sign-in first: the dummy hash that equalises failed
  sign-ins is built at the current cost, so an old hash verifying faster than
  the dummy reopens the enumeration channel the dummy closes.
- The store never sees a stored password
  in the clear.
- **No user enumeration:** authentication errors are coarse (they never
  distinguish "no such account" from "wrong password"), and a missing account is
  still run through a dummy argon2 verify so response time does not leak account
  existence either.
- Provisioning is gated three ways: a valid **session token** (proving sign-in),
  **proof of possession** of the device identity key, and the directory's
  **trust-on-first-use** (a device cannot claim a handle already bound to a
  different key). On *this* path a client never chooses its own handle — the
  server derives it from the authenticated session.
- **Provisioning is not the only path to a directory binding, and the account
  namespace is reserved so that the other path cannot reach it.** The
  directory service (`DirRequest::Register`, port 4720) takes the
  `DeviceAddr` from the request, so its handle *is* client-supplied. It
  refuses any handle containing `/`, and `tacenta_accounts::handle` builds
  every account handle as `"<tenant>/<user>"`, which makes the two namespaces
  disjoint by construction rather than by convention. The check sits on the
  transport path, not in `Directory::register`, because `AccountProvisioner`
  must keep binding `tenant/user` from a validated session. Without it, an
  unauthenticated caller could bind an account-shaped handle, `lookup` would
  return their key to senders, relay auth (which reads the same directory)
  would hand them that address's queued messages, and trust-on-first-use
  would then refuse the rightful owner permanently, provisioning included.
  Both client entry points are deliberate (`Client::connect` for a raw handle,
  `Client::sign_in` for an account). Tests in
  `crates/tacenta-server/tests/handle_claim.rs`.

  **Raw handles are client-chosen and first-come** — that is what
  `Client::connect` is for. The "never client-supplied" guarantee is scoped to
  the account namespace, which is the only place it holds.
- **Sign-in is rate-limited** against online password guessing: too many recent
  failed attempts for an identifier are refused (`AuthError::RateLimited`) before
  the credential check runs, on a sliding window (`tacenta-accounts`,
  `ratelimit`). It is keyed by `(tenant, identifier)`, so it applies whether or
  not the account exists — no existence oracle — and one account's failures
  cannot lock out another. It lives on the in-memory store path (the live
  server path); the Postgres store path is a follow-up. See decision record
  0042.
- **Tenant signup is rate-limited too, one layer up.** `tacenta-accounts` has no
  source address to key on, so the throttle sits where the address exists: the
  gateway checks a per-IP sliding window before every `/v1/tenants` signup and
  every key-management call, keyed by the left-most `X-Forwarded-For` entry a
  trusted proxy set (`tacenta-gateway`, `throttled`). With no proxy in front,
  every request shares one bucket — blunt, and deliberately the safe direction.
  **Remaining gap:** *user* signup inside a tenant is not separately throttled;
  it already requires a valid tenant API key, so the ceiling on it is the
  tenant's own.

### 5. Compromised client or lost device

- **Forward secrecy** (Double Ratchet) bounds what a device compromise exposes
  of *past* messages.
- **Device loss** is recoverable via a pre-provisioned **offline recovery key**
  (0025); proactive **re-keying** is available via rotation (0024). A peer who
  verified the old key sees a safety-number change and should re-verify.

### 6. The page, for the browser head

The TypeScript head runs inside a web page, and the page is its trust
boundary: every script on the page is, to the SDK, the app. Such a script
can read the WebAssembly module's memory (the API key, a password during
sign-in, identity and session keys, plaintexts), replace the global
`WebSocket` and `fetch` the SDK uses (a complete interception no origin
check can see), and read what the app stores; IndexedDB is neither
encrypted nor private from same-origin scripts. The SDK has no defence of
its own against the page. What it does defend: the service document is
checked against the origin it came from (the document's CORS
allow-list says which pages may read it, for the browser's sake; the
WebSocket upgrade checks no `Origin`, because the API key is the guard
there as on the TCP services, and an origin header is a non-browser
client's to set), and a plaintext carriage is
refused off loopback, so a compromised or spoofed document cannot steer the
API key and passwords to another host over a page's own sockets. The
page's defences are the app's: content-security policy, a strict set of
third-party scripts, a Worker for the SDK. On Node, the process's TLS
settings are the design's foundation; `NODE_TLS_REJECT_UNAUTHORIZED=0`
removes it.

## What the server sees, and does not

| Data | Server sees | Why |
|---|---|---|
| Message content | **No** | End-to-end encrypted (tacenta-core) |
| Passwords | **No** | argon2id hashes only |
| API keys / session tokens | **No** | SHA-256 digests only |
| Routing handles (`acme/alice` → `acme/bob`) | **Yes** | The relay must route |
| Message timing and size | **Yes** | Store-and-forward observes them |
| Delivery / presence | **Yes** | The relay tracks delivery watermarks |
| Account identifiers (user usernames; tenant username + email) | **Yes** | The account service holds them; users have no email |
| Tenant membership | **Yes** | The account model is tenant-scoped |
| Signup source IP | **Yes** | The gateway keys its throttle on it (`X-Forwarded-For`) |

Connection exhaustion: every accepted connection on the four TCP
services is served under a cap on how many run at once (a connection past
it is closed at once, `TACENTA_MAX_CONNECTIONS`), a handshake bound on the
relay and an idle bound on the three request/response services, and OS TCP
keepalive so a vanished peer is reaped even on a silent long-lived relay
connection.

The social graph and routing metadata are the server's to see today. **Sealed
sender** (hiding the sender from the relay) and broader metadata minimisation
are planned work, not shipped.

## Non-goals and known limitations (stated, not hidden)

- **Metadata privacy.** The server sees who talks to whom, when, and how much.
  Sealed sender and traffic-shape hiding are future work.
- **The cryptography is tacenta-core's**, used as a pinned dependency and assumed
  correct — deliberately not re-proven (see claims.md). Our risk is *using it
  correctly*, which is tested, not proven.
- **The authorization logic is tested, not proven.** The directory trust rules,
  the relay's per-device authorization, and the account/provisioning
  authorization are the security-critical decisions and are covered by tests and
  the decoder fuzzing, but not yet by machine-checked proofs. This is the open
  verification frontier (planned work), and the honest ceiling on the assurance
  story.
- **Sign-in is rate-limited** (sliding window, keyed by identifier) and tenant
  signup is rate-limited per source IP at the gateway; neither covers *user*
  signup inside a tenant, which is bounded only by the tenant's own API key. The
  sign-in throttle is on the in-memory store path, not yet the Postgres one.
- **Sessions expire** a fixed time after sign-in (24h, decision record 0043) and
  can be **revoked** before their TTL — one token, or every token for a user
  ("sign out everywhere" / compromise response, decision record 0044).
  Refresh/sliding sessions remain a follow-up. Expiry and revocation are enforced
  on **both** the in-memory and the Postgres store paths; the sign-in rate limit
  (above) is in-memory only, since a cross-replica throttle needs a shared
  counter store. TLS certificates are managed manually (0023).
- **Availability / anonymity** (DoS resistance, network-level anonymity) are out
  of scope.

## How to falsify a claim here

Every row above is checkable. "The relay cannot read content" → read
`tacenta-relay`: it moves an opaque `Envelope.payload` and never calls a decrypt
path. "No user enumeration" → read `Accounts::authenticate_*`: one coarse error,
a dummy verify on the miss. "Handles are tenant-namespaced" → the provisioning
handle is `"<tenant>/<user>"`, derived from the session, never client-supplied.
If any of these reads contradicts the claim, the claim is the bug.
