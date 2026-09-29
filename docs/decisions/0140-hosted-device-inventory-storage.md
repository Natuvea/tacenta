# 0140 — hosted device-inventory storage

**Status: experimental. Nothing calls it.** No server route, client, SDK
surface (`sdk/surface.json` lists none of it) or binary uses this code. It
exists so that the storage and signing rules can be read, tested and reviewed
before anything is built on them.

## Decision

Per-account device-inventory state lives in `tacenta-accounts` behind the
existing store split (in-memory, and Postgres behind the `postgres` feature).
The signature over that state is made by a separate component in
`tacenta-server` that holds its own key file. A mutation is committed to the
store first; the signer then signs exactly the committed result, and only while
that result is still the account's current one.

- **What is stored**, per `(tenant, username)`: a generation counter; at most
  eight active bindings (device id, identity public key, capability bits, an
  optional commitment to the binding it replaces); at most eight recent
  revocations with `revocation_floor_generation`, the generation below which
  older revocations have been dropped. Only public keys and counters: no
  secret, no message content. Each completed mutation is also kept under a
  32-byte client retry key with its request and result, so a retry gets the
  original answer. Postgres holds the inventory as one `bytea` row per account
  (`account_device_inventories`) and the retry records in
  `account_inventory_mutations` (migrations 0005 and 0006); the in-memory
  store holds the same and writes it into its snapshot.
- **The issuer key** is one 32-byte secret in its own file, written
  owner-only (`0600`) from the first byte, once, and refused on load if group
  or others can read it. It is separate from account snapshots and database
  rows and is never derived from account or device material. The public key and
  key id are what a deployment would give clients out of band. Details are in
  the module documentation of `inventory_issuer.rs`.
- **Mutations** of one account are serialized by a row lock taken first, a
  separate read after it, and a compare-and-set write, in a transaction the
  store sets to `READ COMMITTED`. The order is in `inventory_tx.rs` and is
  tested without a database.

## The five questions

1. **Does this keep the trusted core small?** Yes. It adds nothing to
   tacenta-core. The core pin moves from `b8c924de` to `5a8f90c1`, the
   revision the group branch already pins; the inventory-statement module
   first appears in core's #158, before it. The product calls that module's
   encoder, verifier and signer. The key-holding component is in the product,
   which is where this record wants it.
2. **Is the behaviour owned by a written specification?** In part. The
   statement's encoding and signature belong to the core (`groups::inventory`
   and its vectors). The lifecycle rules here (exact predecessor generation,
   retry-key scoping, the eight-binding and eight-revocation bounds, the
   revocation floor) have no specification page; their source is the PG-02
   design notes, which are not in this repository. Until a page exists these
   rules are only as reviewed as this code and its tests.
3. **Can the security claim be reproduced?** The claims are the ones in the
   tests: a new key file is `0600` and is created once (`inventory_issuer`
   tests); two racing mutations at one generation admit exactly one
   (`inventory_tx` tests, against a model of `READ COMMITTED`, and
   `tests/pg.rs` against a real database); a superseded retry is not signed
   (`inventory_service` tests). The model is not Postgres, and the Postgres
   tests have not been run against a database (see below).
4. **Does it preserve wire compatibility with a named profile?** The signed
   statement is the core's inventory statement v1 with capability
   `GROUP_EPOCH_V1`. The row, request and snapshot encodings are internal to
   the product and not wire formats. The accounts snapshot gained three
   trailing sections, and snapshots without them still restore.
5. **Is this protocol functionality, or product coupling trying to enter the
   core?** Product: accounts, tenants, sessions, Postgres and the custody of a
   signing key. The core supplies the statement and nothing more. Product code
   reaches it only through `tacenta-core::crypto::groups::inventory`, the one
   module that names the standalone core's inventory types, so a change to
   those types fails to compile there first.

## Considered

- Deriving the issuer key from account or device material. Rejected: a
  compromised or reset account would then move the trust anchor.
- One row per binding, or serializable isolation. Rejected: one bounded row per
  account makes the compare-and-set exact and keeps the model at its stated
  bounds, and the lock plus the guarded write needs no retry loop.
- Reading the inventory in the same statement that takes the lock. This was the
  first version and it loses updates: under `READ COMMITTED` a statement keeps
  the snapshot it took before it waited for the lock, so the waiter sees the
  state from before the other mutation committed.

## Why

A hosted inventory statement is an attestation; the one error it must not make
is attesting to a state the account never held or has left. That is what the
ordering (commit, then sign the current state), the exact-predecessor rule and
the key handling protect, and each has a test that fails without it.

## Not done, and known limits

- **Postgres is compiled in CI, not exercised.** CI runs `cargo clippy` with
  the `postgres` feature on (a compile and lint check). The database tests in
  `tests/pg.rs` need `TACENTA_TEST_DATABASE_URL`, skip without it, and are not
  run by CI. The SQL, migrations 0005 and 0006, and the race against a real
  server have not been run against a database.
- **The in-memory backend is durable only as far as snapshots go**, which the
  server writes on shutdown and, if `snapshot_interval` is set, periodically
  (it defaults to off). A signature can be issued for a mutation a crash then
  loses. Only the Postgres backend commits before the signer signs.
- **Revocation memory is bounded at eight.** Once eight more revocations
  follow it, a revoked binding is forgotten and accepted as new; the floor
  generation in the statement is how a verifier learns that history was
  dropped.
- **Mutation records are never pruned.** They go when the account does.
- **Windows.** The key file's permissions are not set or checked there; it
  inherits its directory's ACL. Publishing the key needs hard links.
- **One issuer per key file.** No rotation, no shared key across server
  replicas, no key backup; a lost file means a new issuer and clients that must
  re-pin.
- The service signs the result of a link only. Replace and revoke are in the
  store and have no signing entry point yet.
- Callers own account-session authorization and proof of possession of the new
  key; nothing here checks either.

## What was run against a real database

On 2026-09-29 the accounts and server tests ran against PostgreSQL 16.2 (a
throwaway server from the `pgserver` 0.1.4 package, in a scratch virtual
environment, removed afterwards): the eight tests in `tests/pg.rs`, the rest of
the `tacenta-accounts` suite with the `postgres` feature, and the server's
`the_server_runs_accounts_on_postgres`. All passed.

**Those passing runs did not show the race fix works.** With the row lock and the
compare-and-set both removed, the two concurrency tests in `tests/pg.rs` still
passed: each transaction is a fraction of a millisecond, so the tasks need not
overlap. A test in `pg.rs` (`interleaving`) now forces the overlap: two
transactions each wait, bounded, after reading the stored state until the other
has read it. With the fix it passes. With both guards removed it fails, because
both writes succeed and one mutation is lost. With either guard removed alone
it still passes: the lock serialises the transactions, and the compare-and-set
refuses the second write, so each covers the other in this scenario. Both stay,
as two independent guards.

Not shown: behaviour under `SERIALIZABLE` or `REPEATABLE READ` (the transaction
sets `READ COMMITTED` explicitly and nothing else was tried), other Postgres
versions, connection loss between the write and the commit, and load.

## What would reopen this

Wiring a route or client to it; a second server instance; a Windows
deployment; a specification page for the lifecycle rules; a result from the
Postgres tests that disagrees with the model (none so far); or a retention need for retry
records or revoked bindings.
