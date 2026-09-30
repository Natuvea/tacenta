# 0140 — hosted device-inventory storage

**Status: experimental. No server route, client, SDK surface
(`sdk/surface.json` lists none of it) or binary calls this code.** It exists so
that the storage and signing rules can be read, tested and reviewed before
anything is built on them. Merging it still changes what a deployment does in
two ways: a server or gateway started against Postgres applies migrations 0005
and 0006 (two tables) at startup, and the in-memory accounts snapshot gains a
header and three sections (see "Snapshots").

## Decision

Per-account device-inventory state lives in `tacenta-accounts` behind the
existing store split (in-memory, and Postgres behind the `postgres` feature).
The signature over that state is made by a separate component in
`tacenta-server` that holds its own key file. A mutation is committed to the
store first; the signer then reads the account's current inventory and signs
the committed result only if it is still that inventory. The account can move
again between that read and the signature, so a statement is a signature over a
state that was current a moment earlier; a verifier orders statements by
generation, and a statement stays valid after the account has moved on (see
"Not done, and known limits").

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
- **What the store refuses before it commits**, in the rules both backends call
  (`crates/tacenta-accounts/src/inventory.rs`):
  - *Identity keys.* Every binding a link, a replacement or a revocation
    supplies is first checked with the core's `validate_identity_key`, the rule
    of check 6 in "Accepting a signed statement" (`identities-and-devices.md`).
    A key it refuses is `InventoryError::IdentityKey`, carrying the core's
    class (`NonCanonical`, `NonContributory` or `NotPrimeOrder`), and nothing is
    stored, no retry record is written and nothing is signed. The function is
    the core's, re-exported by `tacenta_core::crypto::groups::inventory`; there
    is no copy. Because the rule admits exactly one spelling of a key, the store
    compares keys as bytes, which the specification says a policy may. The
    checks are those of the pinned core revision (`dea57eaf` when this was
    written), so a pin change re-reads them.
  - *Replacement predecessors.* A plain link may not carry a
    `replacement_predecessor` (`UnexpectedReplacementPredecessor`), and a
    replacement must carry the commitment of the exact binding it retires in
    the same call (`ReplacementPredecessorMismatch`). The core does not require
    a marker to name a listed binding, because a statement drops revocations at
    or below its floor and a replacement may take a new device id; a verifier
    cannot check it without its own history. The issuer holds the account's
    history, so it applies the stricter rule.
  - The exact predecessor generation, the eight-binding and eight-revocation
    bounds, and the device-id, identity-key and revoked-binding rules that
    `InventoryError` documents.
- **The issuer key** is one 32-byte secret in its own file, written
  owner-only (`0600`) from the first byte, once, and refused on load if group
  or others can read it. It is separate from account snapshots and database
  rows and is never derived from account or device material. The product
  generates and holds this deployment key and hands it to the core's signer; it
  implements no signature or key-agreement primitive. The public key and key id
  are what a deployment would give clients out of band. Details are in the
  module documentation of `inventory_issuer.rs`.
- **Mutations** of one account are serialized by a row lock taken first, a
  separate read after it, and a compare-and-set write, in a transaction the
  store sets to `READ COMMITTED`. The order is in `inventory_tx.rs` and is
  tested without a database.
- **Snapshots.** A snapshot the in-memory store writes starts with an eight-byte
  header and holds seven sections, all required even when empty: tenants, API
  keys, users, sessions, device inventories, link retry records and lifecycle
  retry records. A snapshot cut at any point, including exactly between two
  sections, is refused (`RestoreError::Truncated` names the section it ends
  after), as is one that names a tenant or user it does not hold
  (`RestoreError::Orphan`). The four-section snapshots that servers wrote
  before device inventories have no header and still restore; that shape must
  end after the sessions. The header is what tells a cut copy of a new snapshot
  from an old one. A snapshot written by this tree is not readable by an earlier
  release, and one written by a development build of this branch before the
  header is not readable here.

## The five questions

1. **Does this keep the trusted core small?** Yes. It adds nothing to
   tacenta-core. The core pin is `dea57eaf` (it was `5a8f90c1` when this
   record was first written, and `main` now carries `e06f8f4`, which differs
   from it only in the core's attestation manifests). The inventory-statement
   module first appears in core's #158; #200 adds its acceptance API and the
   identity-key check this record applies at the store, and #205 applies the
   same rule at the session boundaries. The product calls
   that module's encoder, verifier and signer. The key-holding component is in
   the product, which is where this record wants it.
2. **Is the behaviour owned by a written specification?** In part. The
   statement's encoding, its signature and the identity-key rule belong to the
   core (`groups::inventory`, its vectors, and `identities-and-devices.md`). The
   lifecycle rules here (exact predecessor generation, retry-key scoping, the
   eight-binding and eight-revocation bounds, the revocation floor, and the
   replacement-predecessor rule above) have no specification page; their source
   is the PG-02 design notes, which are not in this repository. Until a page
   exists these rules are only as reviewed as this code and its tests.
3. **Can the security claim be reproduced?** The claims are the ones in the
   tests: a new key file is `0600`, is created once, and a file or symlink at
   the exact staging name is never opened (`inventory_issuer` tests); a key the
   identity-key rule refuses, a made-up replacement predecessor and a snapshot
   cut at a section boundary are refused and change nothing
   (`inventory_rules_tests`, `persist` and `inventory_service` tests, and
   `tests/pg.rs`); two racing mutations at one generation admit exactly one
   (`inventory_tx` tests, against a model of `READ COMMITTED`, and
   `tests/pg.rs` against a real database); a superseded retry is not signed
   (`inventory_service` tests). The model is not Postgres, and CI does not run
   the database tests; what was run is under "What was run against a real
   database".
4. **Does it preserve wire compatibility with a named profile?** The signed
   statement is the core's inventory statement v1 with capability
   `GROUP_EPOCH_V1`. The row, request and snapshot encodings are internal to
   the product and not wire formats. See "Snapshots" for what the accounts
   snapshot now carries and which older snapshots still restore.
5. **Is this protocol functionality, or product coupling trying to enter the
   core?** Product: accounts, tenants, sessions, Postgres and the custody of a
   signing key. The core supplies the statement and the identity-key rule and
   nothing more. Product code reaches it only through
   `tacenta-core::crypto::groups::inventory`, the one module that names the
   standalone core's inventory types, so a change to those types fails to
   compile there first.

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
- Leaving the identity-key rule to the signer. The core's signer refuses a
  statement that lists a key the rule refuses, but only after the mutation was
  committed, so an account that held such a key could never be signed for again.
  The store refuses first.

## Why

A hosted inventory statement is an attestation. The store refuses what every
verifier would refuse (an identity key the rule does not admit, a made-up
replacement lineage) before it commits. The ordering (commit, then sign the
current state), the exact-predecessor rule and the key handling keep the signer
from issuing a new signature over a state the account never held or has since
left, and each has a test that fails without it. None of this withdraws a
signature that was already issued.

## Not done, and known limits

- **Postgres is compiled in CI, not exercised.** CI runs `cargo clippy` with
  the `postgres` feature on (a compile and lint check). The database tests in
  `tests/pg.rs` need `TACENTA_TEST_DATABASE_URL`, skip without it, and are not
  run by CI. What was run by hand is under "What was run against a real
  database".
- **The in-memory backend is durable only as far as snapshots go**, which the
  server writes on shutdown and, if `snapshot_interval` is set, periodically
  (it defaults to off). A signature can be issued for a mutation a crash then
  loses. After a restore from an older snapshot the generation counter is back,
  and the next mutation takes a generation that a statement issued before the
  crash already used, with a different active set. The statement format does not
  distinguish two validly signed statements at one generation. Only the
  Postgres backend has committed the mutation durably before the signer signs.
- **A statement stays valid after the account moves on.** Refusing to sign a
  stale retry stops the service issuing a new signature over old state; it does
  not withdraw the statement already issued, whose signature verifies for ever.
  What makes a verifier refuse an old statement is its own freshness rule, which
  the format leaves to it. A device whose link committed but whose response was
  lost has no way to obtain its statement once the account has moved (there is
  no read-and-sign entry point).
- **Revocation memory is bounded at eight.** Once eight more revocations
  follow it, a revoked binding is forgotten and accepted as new; the floor
  generation in the statement is how a verifier learns that history was
  dropped.
- **Mutation records are never pruned, and one account can grow them without a
  limit.** They go when the account does. Deleting an account and registering
  the handle again restarts its generation at zero, and a statement carries no
  incarnation identifier. No code path deletes an account today; the test
  helper `PgAccounts::truncate` removes all of them.
- **The database is trusted for what is signed.** The signer signs the state the
  store returns; a row written by anything else would be signed if it encodes.
  The issuer key and that trust are not yet listed in `docs/claims.md`, the
  threat model or `SECURITY.md`.
- **The key file is read with a plain open.** A symlink at its path is followed,
  its owner and file type are not checked, its size is not bounded before the
  length check, and a staging copy left by a crash between the link and the
  removal is not cleaned up. Creation is careful; loading trusts the directory.
  A staging name that already exists is reported as `AlreadyExists`, the same
  kind as "another starter published first".
- **Windows.** The key file's permissions are not set or checked there; it
  inherits its directory's ACL. Publishing the key needs hard links.
- **One issuer per key file.** No rotation, no shared key across server
  replicas, no key backup; a lost file means a new issuer and clients that must
  re-pin.
- The service signs the result of a link only. Replace and revoke are in the
  store and have no signing entry point yet.
- Callers own account-session authorization and proof of possession of the new
  key; nothing here checks either.

## How the tests were checked

Each rule above has a test that fails when its guard is removed, shown by
changing the code in one place at a time and running the tests (24 changes; the
list and the number of tests each one fails are in the description of pull
request #25). Two are worth stating here, because a claim in an earlier version
of this record was not backed by them. Removing the `O_EXCL` flag from the key
staging file (`create_new(true)` replaced by `create(true).truncate(true)`)
passed all seven issuer tests before the tests planted a symlink and a regular
file at the exact staging name; it now fails two of them
(`a_symlink_planted_at_the_staging_name_is_not_written_through` and
`a_regular_file_planted_at_the_staging_name_is_not_reused`). And a snapshot cut
exactly after the sessions restored with every device inventory reset to
generation zero; every proper prefix of a snapshot is now refused
(`a_snapshot_cut_anywhere_is_refused_and_each_section_boundary_is_named`).

## What was run against a real database

The database tests were run by hand twice, and CI runs neither. Both runs used
the same kind of throwaway server.

**2026-09-30, at `e74d0ba`.** Against PostgreSQL 16.2 from a throwaway
`pgserver` 0.1.4 install: a scratch virtual environment, the package installed
with `pip install --no-deps --require-hashes` from its sha256
(`2b902adff9dbfa65eac0405b914bd16a9d0b04e7710a02e4a172997b436135f4`) and its
three runtime dependencies from the index, a server started in a scratch
directory, then stopped and the environment, data directory and socket
directory removed. The URL was a Unix-socket URL
(`postgres://postgres@localhost/postgres?host=<socket directory>`).

- `cargo test --locked -p tacenta-accounts --features postgres -- --test-threads=1`:
  99 passed, 1 ignored, 0 failed. That is 75 unit tests (including the
  forced-interleaving test below), the 9 in `tests/pg.rs` and the other
  integration tests. The ignored one is the timing measurement, which needs
  `--ignored`.
- `cargo test --locked -p tacenta-server --features postgres --test postgres_server -- --test-threads=1`:
  `the_server_runs_accounts_on_postgres` passed.

**2026-09-29, at an earlier revision of this branch.** The same setup, with the
account tests and the server test. They passed, and they did not show the race
fix works: with the row lock and the compare-and-set both removed, the two
concurrency tests in `tests/pg.rs` still passed, and a forcing test was added.

**What those runs show.** The SQL and migrations 0005 and 0006 apply and behave
as the in-memory store does for the account flow, idempotent retries, the
refusals above, and the handle. Two links, or a revoke and a replace, at one
predecessor admit exactly one (`concurrent_links_at_one_predecessor_admit_exactly_one`
and `concurrent_mixed_mutations_at_one_predecessor_admit_exactly_one`), but those
two tests do not show that the row lock or the compare-and-set does the work:
each transaction is short enough that the tasks need not overlap.

**The forced-interleaving test.**
`two_transactions_that_both_read_generation_one_admit_exactly_one` (module
`interleaving` in `pg.rs`) makes the overlap happen: after reading the stored
state each transaction waits, for at most two seconds, until the other has read
it as well. With both guards in place it passes: the lock keeps the second
transaction from reaching its read until the first commits, the wait expires,
and the second is refused as stale. On 2026-09-30 it was run again with each
guard removed in the SQL: with both removed it fails; with only the lock removed
it passes; with only the compare-and-set removed it passes. Each guard alone is
enough for this scenario, so the test cannot say which of them is doing the
work, and both stay as independent defences.

**What they cannot show.** Behaviour under `SERIALIZABLE` or `REPEATABLE READ`
(the transaction sets `READ COMMITTED` explicitly and nothing else was tried),
other Postgres versions, connection loss between the write and the commit, load,
and any of it in CI.

## What would reopen this

Wiring a route or client to it; a second server instance; a Windows
deployment; a specification page for the lifecycle rules; a result from the
Postgres tests that disagrees with the model (none so far); or a retention need
for retry records or revoked bindings.
