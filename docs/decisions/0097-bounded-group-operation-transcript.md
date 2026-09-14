# 0097 — bounded group operation transcript

## Decision

The bounded group harness emits one version-one transcript record after every
operation attempt. A record contains the fixture ID, operation ordinal, group
ID, accepted revision and roster digest before and after the operation,
invitation disposition, logical-send and per-recipient dispositions, application
effect, authenticated provider peer, provider result class, provider state
effect, durable action, and snapshot generation.

Each field is an explicit enum, opaque byte value, or absent value; the record
never substitutes a relay address for the authenticated provider peer.
Provider result class and provider state effect remain independent. Durable
action is `committed`, `failed`, `unknown`, or `not_required`; an unknown
or failed required action blocks the external effect named by the record.

A golden trace lists the accepted neighbour for every G1 fixture and a separate
trace for each targeted mutation. Comparison is field-by-field against the
versioned schema. An independent reader needs only the normative contract,
fixture inputs, and golden transcript; it must not infer expected outcomes from
product implementation code.

## Considered

- Log unstructured test output.
- Record only a final pass/fail value.
- Use a versioned compact operation transcript.

## Why

The group protocol crosses product policy, provider state effects, persistence,
and transport boundaries. A compact record makes each claimed effect attributable
without collapsing crypto success into application authorization or a durable
commit into relay acceptance.

## What would reopen this

A real cross-repository core helper, a new durable-store format, or a production
group protocol requires a successor schema and compatibility rule. This record
does not expose transcript data through the SDK or treat a harness trace as
production telemetry.
