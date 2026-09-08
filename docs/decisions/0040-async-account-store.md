# 0040 — a backend-agnostic async account store

## Decision

The account operations move behind `AccountStore`, an enum with async methods
that the transport and the provisioner drive without knowing the backend:

```
enum AccountStore { Memory(Box<Mutex<Accounts>>), #[cfg(feature="postgres")] Postgres(PgAccounts) }
```

Errors unify to `StoreError { Signup, Auth, Backend }`; a `Backend` failure (a
database error, which only the Postgres arm can produce) surfaces on the wire
as `AccountResponse::ServerError` / `ProvisionOutcome::ServerError` — new,
transient "the request was not applied" responses. The transport's
`AccountServer` holds an `Arc<AccountStore>` and its handler is async; the
`Provisioner` trait's `provision` becomes async (`-> impl Future + Send`, so a
connection can be served on a spawned task). This commit is behavior-preserving
— the server still constructs the `Memory` backend; selecting Postgres is the
next step.

## Considered

- **`Arc<dyn AccountStore>` with the `async-trait` crate.** The idiomatic
  runtime-polymorphism route, and more extensible. Rejected for now: it adds a
  dependency and boxes every call, for two backends that a `match` dispatches
  just as well. An enum keeps it dependency-free and avoids dyn dispatch.
- **Generic over the store (`S: AccountStore`).** No dyn, no boxing — but the
  backend is a *runtime* choice (config), and threading a generic all the way
  up would force the server to monomorphise both backends and branch its whole
  serve wiring. The enum makes the choice a value, not a type.
- **Native `async fn` in the `Provisioner` trait.** Cleaner to write, but a
  native async fn in a trait does not let a generic caller assume the future is
  `Send`, so spawning the connection would not compile. `-> impl Future + Send`
  in the trait (with `async fn` in the impl) states the `Send` bound the
  spawn needs.

## Why

The point is one surface, two backends, chosen at runtime, with no new
dependency. The enum's in-memory arm locks the `Mutex`, does its synchronous
argon2 work, and drops the guard — all within a non-`await` region, so the
future stays `Send` and the guard never crosses a suspension point (the same
lock-not-across-await discipline the rest of the server follows). The `Backend`
error and its `ServerError` responses are the honest addition a database forces:
an in-memory store cannot fail infrastructurally, but a database can, and the
protocol now has a way to say so rather than dropping the connection.

## What would reopen this

- **Selecting Postgres in the server.** Config to point the server at a
  database, construct `AccountStore::postgres`, and skip the account snapshot
  (Postgres persists itself) — the next slice.
- **A third backend, or a plugin store.** Two variants suit an enum; a third
  (or an out-of-tree backend) is the point to revisit `dyn AccountStore` +
  `async-trait`.
- **The directory and relay** get the same treatment when they move to
  Postgres — likely the same enum shape, or a shared store trait if the pattern
  repeats three times.
