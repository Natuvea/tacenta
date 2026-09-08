# 0043 — session expiry

## Decision

Session tokens expire a fixed time after sign-in. `Accounts` stores each
session's `expires_at` (unix seconds) alongside its `(tenant, username)`, sets
it to `now + SESSION_TTL_SECS` (24 hours) when `sign_in` issues the token, and
`validate_session` returns `None` for a token whose `expires_at` has passed —
exactly as it does for an unknown token. A leaked or stolen token is otherwise
valid forever; the TTL bounds that window.

Shape decisions:

- **Expiry stored per session, checked at validation.** The session map value
  gains a `u64` expiry; `validate_session` filters on it. No background timer.
- **Explicit clock for testability.** `validate_session` reads the system clock;
  `validate_session_at(now, …)` takes an explicit one, mirroring the sign-in
  rate limiter (0042). `sign_in_at(now, …)` stamps the expiry from the same
  `now`, so issue and validation share a clock in tests.
- **Lazy, not swept.** An expired entry is left in the map (validation is a
  read, `&self`); it is overwritten on the next sign-in. A periodic sweep of
  expired rows is a follow-up — until then the map can accumulate dead sessions.
- **Persisted.** The snapshot format (0022) carries the expiry (`put_u64` /
  `take_u64`), so a restored session keeps its original deadline rather than
  being renewed by the restart. The snapshot format is unversioned and this
  changes it; acceptable pre-alpha (no deployed snapshots), noted here.

## Verification

Unit and integration tests (`tests/session_expiry.rs`) with an injected clock:
a token is valid up to but not including the TTL boundary, expired at and after
it, and its lifetime is measured from issue time (a sign-in far in the future is
valid for the full TTL from *then*). The existing snapshot round-trip test
(`persist.rs`) covers that expiry survives restore (the token, issued fresh,
still validates). Tested mechanism, not a proof; recorded in `claims.md` under
"Tested, not proven".

## Considered

- **A background reaper.** Cleaner memory behaviour, but adds a task and a lock
  discipline for a pre-alpha in-memory store; lazy expiry plus a future sweep is
  enough for now, and the durable store (0030) changes this surface anyway.
- **Sliding / refresh sessions** (extend on use). Better UX, but it is a policy
  choice with its own security trade-offs (a stolen-but-used token never
  expires); a fixed TTL is the conservative default, and refresh is a documented
  follow-up.
- **Server-side revocation now.** Explicitly invalidating one session before its
  TTL is a real need (logout-everywhere, compromise response) but is a separate
  mechanism (a revocation set or a store delete); scoped as a follow-up so the
  TTL — the higher-leverage "not valid forever" fix — lands first.
- **Encoding expiry into the token.** A signed token carrying its own expiry
  needs no server state, but the store already holds session state (it keys on
  the hash), so a stored expiry is simpler and also enables future revocation.

## What would reopen this

- **Revocation and refresh** (above) — the two obvious next session features.
- **The Postgres store path (done).** `PgAccounts` sessions carry an `expires_at`
  column (migration `0002`), set to `now() + the TTL` on sign-in, and
  `validate_session` filters `expires_at > now()` — parity with the in-memory
  store, exercised against a real Postgres in `tests/pg.rs`.
- **A configurable / per-tenant TTL.** `SESSION_TTL_SECS` is a constant; a real
  deployment may want it tunable.
- **A sweep** of expired rows (done): `sweep_expired_sessions` on both stores
  (in-memory `retain`, Postgres `DELETE ... WHERE expires_at <= now()`), run from
  the server's snapshot tick. Remaining: sweep when no snapshot interval is set
  (today it rides that tick).
