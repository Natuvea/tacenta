# Side-channel reasoning

Where Tacenta's own code makes a timing or side-channel choice, the reasoning is
written here rather than left implicit — so a reviewer can check it, and so a
future change that breaks the assumption is visible. This covers only Tacenta's
code; the cryptographic side-channel posture of the primitives is tacenta-core's,
used as a pinned dependency and assumed sound (see [claims.md](claims.md)).

Scope note: these are **arguments**, not machine-checked constant-time proofs,
and the distinction has three levels rather than two. Nothing here is formally
verified constant-time — no type system, no static analysis, no proof. One
argument (account existence) is additionally backed by an **empirical**
measurement, a dudect-style Welch's t-test over interleaved input classes; that
is evidence a regression would show up, not a proof of its absence, and dudect
is a measurement tool, not a formal one. The rest are code-level reasoning a
reviewer should verify. Each claim below states which of the three it is.

## Authentication timing — no user enumeration

The risk: an attacker learns whether an account exists (a user by username, a
tenant by username or email) by timing the difference between "no such account"
(fast) and "wrong password" (slow, because it runs a password hash).

The defence, in `Accounts::authenticate_*` and the Postgres store:

- **A missing account still runs a password verify** against a fixed dummy
  argon2 hash, so a nonexistent account takes the same order of time as a real
  account with a wrong password.
- **The error is coarse.** `InvalidCredentials` never distinguishes the two
  cases, so neither the response nor its timing separates "no account" from
  "wrong password".

Limits: the dummy verify equalises the argon2 cost, which dominates; it does not
claim byte-for-byte identical timing, and it assumes the pinned argon2id
parameters (m=19 MiB, t=2, p=1, `crates/tacenta-accounts/src/lib.rs`) are the
same on both paths (they are — the same call). Argon2's own verify is
constant-time with respect to the password by construction.

The **sign-in rate limiter** (`ratelimit`, decision record 0042) preserves this
property. It is keyed by `(tenant, identifier)`, not by whether the identifier
resolves to a real account, so a missing and an existing account accrue failures
and become blocked identically — the `RateLimited` outcome is not an
account-existence oracle. A blocked attempt returns before the argon2 verify, so
it is *faster* than an unblocked one; that timing difference reveals only that
the key is currently throttled (a fact already implied by the `RateLimited`
error), never whether the account exists.

Two caveats, both also stated in [threat-model.md](threat-model.md):

- **The rate limiter is on the in-memory store path only.** The Postgres path
  has no throttle yet -- a cross-replica one needs a shared counter -- so
  there the dummy verify's timing equalisation is the whole of the sign-in
  side-channel defence, and the cost of guessing a known account's password
  is bounded by argon2 and the gateway, not by a per-identifier ceiling.
- **Sign-in is a tenant-existence oracle, and that is accepted.** Both store
  paths refuse an unknown tenant before argon2 runs, with a distinct response
  (`UnknownTenant`), so the reply and its timing say whether a tenant
  identifier exists. The argument for accepting it: a tenant identifier is a
  ULID -- a 48-bit millisecond timestamp, which is guessable, and 80 bits
  from the OS random source, which is not -- and it is not a secret in the
  first place (every user of a tenant is told it in order to sign in). An
  attacker who can guess 80 random bits does not need an oracle, and one who
  cannot learns from it only whether an identifier they already hold is
  live. It is not a defence to lean on for anything with less entropy.

## API keys and session tokens — lookup timing is uninformative

API keys (`tct_` + 256 bits of randomness) and session tokens (`ses_` + 128
bits) are looked up by their SHA-256 digest: the store keys a map (in Postgres,
a primary-key index) on `sha256(token)`. The map/index lookup is **not**
constant-time.

Why that is acceptable: the value being looked up is high-entropy random. To
turn any lookup-timing signal into a hit, an attacker would need to already
possess a token whose hash collides in the probed bucket — i.e. essentially to
already know a valid token. Guessing a 128–256-bit secret is infeasible
regardless of lookup timing, so the non-constant-time lookup leaks nothing an
attacker can use. This is the standard argument for hashing high-entropy bearer
tokens for storage; it does **not** hold for low-entropy secrets, which is why
passwords go through argon2 and not this path.

## Passwords at rest and in comparison

Passwords are compared only via argon2id's `verify_password`, which is
constant-time in the password. They are never compared as raw strings and never
stored in the clear (argon2id hash only). API keys and session tokens are
likewise stored only as digests, so a database read never yields a usable
secret.

## What is out of scope here

- **The cryptographic primitives** (AEAD, the ratchet, key agreement, ML-KEM):
  their constant-time and side-channel properties are tacenta-core's, assumed, not
  re-established here.
- **Micro-architectural channels** (cache, speculative execution, power) are not
  analysed; Tacenta targets the protocol-level timing oracles above, not
  hardware side-channels.
- **Formal constant-time verification** is not done — the above are code-level
  arguments. A **dudect-style empirical check** now backs the account-existence
  argument specifically: `crates/tacenta-accounts/tests/timing.rs` times
  `authenticate_user` for a real-account-wrong-password input class against a
  no-such-account class, interleaved, crops scheduler outliers, and computes
  Welch's t-statistic — a large |t| would be evidence the dummy-verify had
  regressed and the two paths became distinguishable. It is `#[ignore]`d (wall-
  clock timing would make CI flaky) and run on demand:
  `cargo test -p tacenta-accounts --test timing -- --ignored --nocapture`.
  This is a measurement and a regression smoke check, not a rigorous machine-
  checked constant-time proof; argon2 itself is not constant-time and does not
  need to be (the same verify runs on both paths). The other timing arguments
  above (token lookup, session validation) are not yet covered by an empirical
  harness.
