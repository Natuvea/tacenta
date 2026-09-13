# 0091 — durable client operations

## Decision

The client will persist a versioned combined operation snapshot before any
operation crosses a transport or acknowledgement boundary. The snapshot carries
opaque provider state, immutable prepared-send bytes, application/group state,
inbox dispositions, deferred items, deduplication state, delivery cursor and a
monotonic generation. The native reference store publishes the complete
snapshot through the existing atomic-file writer; platform stores provide the
same commit/recover port.

A write has three distinct outcomes: `committed`, `failed`, or `unknown`.
`unknown` freezes every affected operation until recovery selects a durable
generation. Dispatch, cumulative ACK and application delivery require the
corresponding durable disposition; they never proceed from an uncommitted
working copy.

The trusted core stays unchanged: this is product operation coordination over
opaque provider bytes. Its behaviour is owned by this record and the future
operation-store specification; it establishes no wire compatibility or
reproducible security claim until the real provider/store integration tests
pass.

## Considered

- Continue with independent session blobs and best-effort receive handling.
- Add a database-specific transaction layer first.
- Use a narrow combined snapshot and explicit outcome port first.

## Why

The current session blob and secure-store counter protect pieces of client
state, but they do not make a provider state advance, ciphertext handoff,
inbox record and cumulative ACK one atomic operation. Group fan-out requires a
durable immutable record per recipient, and direct messages use the same
provider sessions. One explicit operation boundary avoids silently extending
the existing best-effort receive semantics into a group claim.

## First harness

The initial fault harness uses opaque bytes and deterministic injected failures
at preparation, provider-state mutation, counter update, snapshot publication,
transport handoff, inbox commit, ACK and application-event consumption. Every
schedule verifies that no output uses uncommitted state and no ACK crosses an
item without a durable accepted, rejected or deferred disposition. It does not
claim that the current client already has these properties.

## Consequences

GC-01's prepared request becomes an outbox candidate; GC-02 must expose the
provider outcome/state effect required to snapshot it; GC-03 adds the store and
harness before group dispatch or durable receive integration. Existing public
DM APIs remain unchanged while these private stages are introduced.

## What would reopen this

A platform store that cannot implement committed/failed/unknown recovery, a
need for multi-process writers, or measured group workloads that make a single
snapshot unsuitable requires a new decision. Any replacement retains the
durable boundary before dispatch, ACK and application delivery.
