# 0039 — the Postgres account store: first cut of the durable store

## Decision

The durable store (decision record 0030) begins with **accounts**, as a
Postgres-backed store `PgAccounts` living behind a `postgres` feature in
`tacenta-accounts` (`src/pg.rs`, `migrations/`). It mirrors the in-memory
`Accounts` surface — sign up, authenticate, sign in, validate a session,
resolve a handle or an API key — against a database.

Shape decisions:

- **Feature-gated inside `tacenta-accounts`, not a separate crate.** The store
  reuses the crate's existing private logic — argon2id hashing, the coarse
  errors, the timing dummy-verify, input normalisation, the prefixed sortable
  ids, API-key/session hashing — so it belongs where that logic lives. The
  `sqlx` dependency is `optional` and the `postgres` feature is off by default,
  so the in-memory store and everything that depends on it (transport, client,
  server) pull none of it.
- **Runtime `sqlx`, not the compile-time query macros.** Queries are plain
  `sqlx::query`, so the crate builds with no database present; only the tests
  need one. Migrations are embedded SQL run idempotently on start.
- **Uniqueness is a database constraint.** Global tenant username/email and
  per-tenant user username are named unique constraints; the store maps a
  unique-violation back to `UsernameTaken` / `EmailTaken` by constraint name.
  This is what 0030/0033 meant by "the uniqueness indexes become database
  constraints" — the invariant is now enforced by the database, not an
  in-memory map. (Users no longer carry an email — decision record 0045; the
  `users_tenant_email_key` constraint was dropped in migration `0003`.)

This is the first cut and is **not yet wired into the server**: the server
still runs the in-memory snapshot store (0022 / accounts persistence). Making
the server choose Postgres needs an async store abstraction, and the directory
and relay need their own Postgres stores — both follow-ups.

## Verification

The store is exercised against a **real Postgres** (a Docker `postgres:16`):
the whole flow — tenant + user signup with constraint-enforced uniqueness,
tenant and user authentication, sign-in + session validation, handle
resolution, and cross-tenant isolation — passes. The integration test is
opt-in: it runs only when `TACENTA_TEST_DATABASE_URL` is set and skips cleanly
otherwise, so `cargo test` needs no database. CI **compile-checks** the feature
(`cargo clippy -p tacenta-accounts --features postgres`) so it cannot rot, but
does **not run** the database tests — a CI Postgres is a follow-up, so today
the DB assertions are verified locally, not in CI. That gap is deliberate and
recorded, not silent.

## Considered

- **A separate `tacenta-accounts-pg` crate.** Cleaner dependency isolation, but
  it cannot reach the crate's private hashing/validation/id helpers or
  construct its opaque types without adding public constructors, and it would
  duplicate that logic. The feature gate gives the same isolation (sqlx is
  off by default) without the duplication.
- **Compile-time `query!` macros.** They check SQL against a live database at
  build time — which would make every build (and CI) need a database or a
  checked-in `sqlx-data.json`. Runtime queries keep the build database-free at
  the cost of no compile-time SQL check; the integration test covers the SQL
  instead.
- **`diesel` / `tokio-postgres`.** Diesel is synchronous and macro-heavy;
  tokio-postgres is lower-level with no migrations or pooling to speak of. sqlx
  gives async, a pool, and migrations, which is the whole job here.

## What would reopen this

- **An async store trait + server wiring.** To let the server run on Postgres,
  the account operations become an async trait both stores implement, and the
  transport handler and server construction select one. That is the next slice.
- **A CI Postgres.** A service container so the DB integration tests run in
  CI, not only locally.
- **Directory and relay on Postgres.** Accounts are the relational, uniqueness-
  heavy store; the directory (identity/prekey bindings) and the relay (the
  message queue) get their own Postgres stores next, replacing their snapshots.
- **TLS to Postgres.** The feature omits a TLS backend for now (local Postgres
  is plaintext); a real deployment adds a rustls-ring TLS feature.
