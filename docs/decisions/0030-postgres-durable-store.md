# 0030 — PostgreSQL as the durable store, from the start

## Decision

The durable persistence work (which supersedes the whole-state snapshot
of decision record 0022) lands on **one PostgreSQL**,
serving both the directory and the relay, from the first cut. Not a
distributed key-value store, not a split of relational store plus a
dedicated message queue — a single, ordinary Postgres.

This records a direction ahead of the implementation. Today the server is
still in-memory with periodic and shutdown snapshots (0022); this fixes
what the incremental store is when that work begins.

## Considered

- **SQLite (embedded).** The one genuine alternative. It embeds directly in
  the Rust server — no separate process — is transactional, and would clear
  the directory plus the relay queue at pre-alpha scale without strain; it
  fits the single-core, minimal-operations posture. What it cannot give is a
  cross-process transactional notify (below), so a later multi-pod relay
  means either moving to Postgres anyway or bolting on LiteFS/rqlite. The
  right choice only if we commit deliberately to single-node for the
  foreseeable term; rejected because it defers a foundation decision to a
  migration rather than settling it now.
- **FoundationDB.** Ordered transactional KV with a strong correctness
  pedigree (deterministic simulation testing). But it serves a throughput
  and horizontal-scale regime we are an order of magnitude below, at a
  heavier operational cost and with less mature Rust bindings. Solving a
  bottleneck this design does not have.
- **Aerospike.** A flash-optimized distributed KV for millions of ops/sec
  over very large key spaces. Every axis it wins (raw KV throughput, flash
  economics, horizontal KV scale) is one we do not compete on; its strong
  consistency is a paid feature; its heritage single-record eventual
  consistency is weakest exactly where the directory is strictest (atomic
  prekey consumption, first-claim-wins). The clearest case of the right tool
  for a question we are not asking.
- **Split: Postgres for the directory, a durable queue (NATS JetStream)
  for the relay.** Purpose-fits each shape, but a store-and-forward relay
  queue sits far below a single primary's write ceiling, so the second
  system is cost without a matching benefit — and it forfeits the transactional-notify
  guarantee below. Revisit only if the relay write path is ever measured to
  bind.
- **Keep the whole-state snapshot (0022).** Correct but O(state) per save
  and unversioned; it does not scale to a large directory. It was always the
  honest first step, not the destination.

## Why

The decision rests on the shape of the workload:

- **The database is not the expected bottleneck.** A single primary
  sustains commit rates well above what a store-and-forward relay of this
  shape writes. The wall in such systems is fan-out delivery (socket-write
  syscalls and a per-recipient lock), which scales horizontally on the
  delivery tier, not the store. So a store with more raw throughput buys
  headroom over a wall that already sits far away.
- **The directory's hard invariants are one SQL transaction.** Atomic
  one-time-prekey consumption (each handed out exactly once) and
  first-claim-wins trust-on-first-use are multi-step serializable
  constraints. A unique constraint plus a transaction makes them correct by
  construction; a hand-rolled equivalent over an eventually-consistent KV is
  a landmine.
- **Transactional notify is a lever only Postgres gives for free.** Emitting
  a `LISTEN/NOTIFY` inside the same transaction as the row write gives
  torn-read-free cross-pod fan-out with no outbox. Every alternative store
  needs an outbox or two-phase coordination to match it. Choosing Postgres
  now keeps that lever available for the day a multi-pod relay is wanted,
  at no present cost.
- **Fewer moving parts is the ethos.** One well-understood store, versus a
  cluster to size and operate, matches the single-core discipline. Adding a
  component for a problem this design does not have is negative work.

The relay queue maps cleanly onto this: store-and-forward, FIFO, redeliver
where the delivered marker is null — a shape that sits well under a single
primary's write ceiling. Tacenta's relay is lighter still (raw TCP, no
fan-out tier yet), so the store is even less likely to bind first.

## What would reopen this

- **A deliberate single-node-forever posture.** If Tacenta commits to a
  single process for the foreseeable term and weights the embedded
  single-binary story above multi-pod readiness, SQLite becomes the better
  answer and this reopens.
- **Measured write-path pressure.** If the relay or directory write path is
  ever measured approaching a single-primary ceiling within a real horizon,
  the levers are batched appends and commit tuning first, then read replicas
  or cells — and a purpose-built queue for the relay comes back onto the
  table.
- **Cross-region fan-out.** `LISTEN/NOTIFY` is per-database; a cross-region
  notify requirement forces a replicated pub/sub transport and changes the
  calculus.
- **A connection-count (not throughput) ceiling.** Many service replicas
  summing past what one primary holds is the standard trigger for a
  transaction-mode pooler in front of the query path — a later lever on top
  of this decision, not a reversal of it.
