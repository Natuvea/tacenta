# 0022 — server persistence and graceful shutdown

## Decision

`tacenta-server` can survive a restart. With a data directory configured
(`Config::data_dir`, `TACENTA_DATA_DIR`), the server loads both snapshots
on `bind` and writes them back on graceful shutdown:

- **The directory gains snapshot/restore**, mirroring the relay's
  (decision record 0016): `Directory::snapshot` serializes each registered
  device's address, identity key, and bundle; `Directory::restore` replays
  them through the ordinary `register`, so a reloaded directory carries the
  same trust-on-first-use bindings as a live one — nothing bypasses the
  binding invariant. Only the entries are stored; the per-user device index
  is regenerated on restore.
- **The server loads on `bind`** from `directory.snapshot` and
  `relay.snapshot` in the data directory. An absent file means first run
  (start empty); a present-but-corrupt file fails startup rather than
  silently discarding state.
- **The server saves on graceful shutdown.** `serve` now selects over the
  two service futures, a caller-supplied `shutdown` future
  (`serve_until`), and Ctrl-C (`tokio::signal`), then writes both snapshots
  before returning. `serve_until` makes shutdown injectable, so the save
  path is tested without sending a signal (`tests/persistence.rs`).

## Considered

- **Persist on every write.** Snapshot after each registration and each
  enqueue. Correct against a crash, but it rewrites the whole snapshot per
  mutation — O(state) per operation. The right shape is an append log or a
  real database, which is the incremental-persistence follow-up; a
  whole-state save at shutdown is the honest first step, matching the
  relay's existing snapshot model.
- **A periodic timer save.** Bounds crash loss to the interval without a
  write per mutation. Worth adding, but it is a tuning knob on top of the
  shutdown save, not a replacement — deferred so the first cut stays
  simple. `Server::persist` is public so a periodic loop can call it.
- **No graceful shutdown; rely on the OS.** Then there is no point at which
  to save, so persistence would be load-only. The signal handler is what
  makes the save meaningful, which is also why the `tokio` `signal`
  feature is enabled here.

## Why

A server you can point at is only useful across restarts if it does not
forget every registration when it stops. The directory snapshot was the
missing half (the relay already had one), and a shutdown hook is the point
at which whole-state persistence is both simple and consistent — no lock is
held across a write, and the snapshot is of a quiescent-enough state. Load
on `bind` closes the loop. `tests/persistence.rs` proves it end to end: a
client registers against a running server, the server shuts down and
persists, a fresh server binds from the same directory, and the client then
authenticates to the new relay *without re-registering* and finds its
bundle — the registration crossed the restart.

## What would reopen this

- **Crash consistency.** A periodic snapshot now bounds the loss to one
  interval (`Config::snapshot_interval` / `TACENTA_SNAPSHOT_SECS`, a timer
  branch in `serve_until` calling `persist_state`). A crash or `kill -9`
  still loses at most that interval, and each save rewrites the whole
  state; an append log or database is what makes it genuinely durable and
  incremental. This is the durable-persistence follow-up.
- **Snapshot format is whole-state and unversioned.** Fine at this size,
  but a growing directory will want an incremental format, and any format
  change wants a version byte to migrate rather than fail as "corrupt".
- **No integrity protection on the snapshot files.** They are plain bytes
  on disk; a deployment handling real data wants them on encrypted storage
  or with a MAC, so a tampered snapshot cannot inject key material.
