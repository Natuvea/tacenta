# 0042 — sign-in rate limiting

## Decision

Sign-in is throttled against online password guessing by a sliding-window
failed-attempt limiter in `tacenta-accounts` (`src/ratelimit.rs`). Too many
failed attempts for a key within a window refuse further attempts with
`AuthError::RateLimited` **before** the credential check runs; a success clears
the key. Defaults: five failures in a 60-second window.

Shape decisions:

- **Keyed by `(tenant, identifier)`, not by resolved user.** The throttle
  applies whether or not the identifier names a real account, so — like the
  dummy-verify (0-series side-channels) — it is not an account-existence oracle,
  and one account's failed attempts cannot lock out a *different* account.
- **Sliding window, no separate lockout.** A failure counts while it is within
  the window of `now`; once the window's worth of failures have aged out, the
  key recovers on its own. Simpler than a fixed lockout timer and self-healing.
- **Blocked attempts short-circuit before argon2.** A blocked key never reaches
  the password verify, so the limiter also sheds the argon2 cost of a guessing
  flood rather than paying it. The resulting timing difference reveals only that
  the key is throttled (already stated by the error), not account existence.
- **Explicit clock.** `sign_in` reads the system clock; `sign_in_at(now, …)`
  takes an explicit unix-seconds clock, so the policy is deterministically
  testable and a transport that also rate-limits by source address can supply
  its own time source.

## Verification

Unit tests (`ratelimit.rs`) cover the ceiling, the window recovery, the
success-clears-count reset, and key independence. Integration tests
(`tests/ratelimit.rs`) drive the **real `Accounts` store** with an injected
clock: five failures then a sixth refused even with the correct password; the
block lifting after the window; a success before the ceiling resetting the
count; and a missing account throttling identically to a real one without
locking the real one out. This is a tested mechanism, not a proof; it is
recorded in `claims.md` under "Tested, not proven" and its
existence-oracle-freedom is argued in `side-channels.md`.

## Considered

- **Baking the check into `authenticate_user`.** That method is `&self` (a pure
  credential check) and is called from more than one path; making it stateful
  would spread the limiter's mutation across the API. Gating the stateful
  `sign_in` (`&mut self`, the login entry point) keeps the limiter in one place.
- **A fixed lockout period after N failures.** Equivalent to the window for the
  common case but adds a second tunable and a "still locked though quiet" state;
  the sliding window subsumes it.
- **Per-IP keying here.** The account layer does not see the source address —
  that belongs to the transport. Identifier-keying defends the *account*
  (guessing one password); source-address keying (signup spam, distributed
  guessing) is transport-level follow-up.
- **A crate-level limiter shared by both stores.** The limiter lives on the
  in-memory `Accounts`, which is the live server path today (0039); the Postgres
  path does not yet carry it. A shared limiter in `AccountStore` is the natural
  home once the server runs on Postgres.

## What would reopen this

- **Signup throttling.** Needs a transport-level source-address key; not done.
- **The Postgres store path.** When the server moves to Postgres (0039), the
  limiter moves up to `AccountStore` (or a shared component) so both backends are
  covered; today only the in-memory path is.
- **Configurable policy.** The ceiling/window are constants; a real deployment
  may want them tunable (and per-tenant), and may want the counters in a shared
  store so the limit holds across multiple server replicas rather than per-pod.
- **Tenant authentication.** `authenticate_tenant` (API-key issuance path) is not
  yet rate-limited; tenant login is rarer but the same shape applies.
