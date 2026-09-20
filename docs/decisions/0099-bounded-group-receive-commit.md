# 0099 — bounded group receive commit

## Decision

The client adapter applies `GroupReceiver` to the authenticated peer and
canonical application context only in a candidate operation state. It records
that context, its standalone-core payload commitment, the provider state
effect, and the resulting receive disposition in one versioned inbox record.
It publishes the combined snapshot before returning the disposition to the
relay acknowledgement or application-delivery paths.

The initial record tag is `TCGR`. Its fixed order is the provider state effect
code, canonical application-context bytes, the 32-byte payload commitment, and
the disposition. An accepted or duplicate disposition stores its stable event
ID; a terminal rejection stores its refusal code; deferred has no application
event. The snapshot also retains the encoded context in its dedup collection.

The adapter changes its live receiver and snapshot only after the store returns
`committed`. A `failed` or `unknown` result returns a frozen operation error,
leaves both live values unchanged, and gives no receive disposition to a caller
that could acknowledge or deliver it. A terminal group rejection still commits
the supplied provider state effect because pairwise processing may already have
advanced or terminally consumed its cryptographic state.

## Considered

- Return policy decisions before recording them.
- Drop provider state for rejected group content.
- Commit the context, dedup key, and disposition independently.
- Publish one candidate snapshot before returning the disposition.

## Why

This supplies the concrete coordinator edge deferred by decisions 0096 and
0098. It makes acceptance, rejection, and deferral recoverable and prevents a
cumulative ACK or an application event from describing a receive state that was
never published.

## What would reopen this

Live provider state export, a public SDK receive API, or a replacement durable
store needs a successor that preserves this ordering and record meaning.
