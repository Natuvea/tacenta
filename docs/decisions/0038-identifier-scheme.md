# 0038 — identifier scheme: prefixed and sortable, but not secrets

## Decision

Two shapes, chosen by whether the value is an identifier or a secret.

- **Identifiers** are `"<prefix>_<ulid>"`: a type prefix then a ULID — a 48-bit
  millisecond timestamp and 80 bits of randomness, Crockford-base32 (26 chars).
  The prefix names the kind (`ten_…`) and is greppable; the ULID makes the id
  **sort lexicographically by creation time**. `TenantId` uses this
  (`id::prefixed`), and every future opaque entity id (messages, rooms,
  devices-as-entities) does too.
- **Secrets** are `"<prefix>_<random>"`: a type prefix then full random entropy,
  hex-encoded, **not sortable**. `ApiKey` (`tct_` + 256 bits) and `SessionToken`
  (`ses_` + 128 bits) stay this way (`random_token`).

The ULID generator is hand-rolled in `tacenta-accounts` (`src/id.rs`), no
dependency.

## Considered

- **Make everything sortable (ULID for secrets too).** Maximally uniform, but
  wrong for secrets on two counts: a sortable token leaks its creation time,
  and ULID's 80-bit random tail is weaker than the 128–256 bits the tokens
  carry now. The prefix already gives secrets the one thing an id-scheme should
  give them — type identification and secret-scanning — without making them
  ordered. So identifiers sort; secrets do not, deliberately.
- **The `ulid` crate.** Battle-tested and less code to own, but it is a small,
  well-understood construction (timestamp + random, base32) that fits the
  repo's hand-rolled, dependency-light style (like the wire codec), and avoids
  another pinned crate in the dependency ledger.
- **UUIDv4.** No ordering — the property we wanted. **UUIDv7** would sort, but
  it is unprefixed and its hyphenated hex is less compact and not
  type-tagged; the prefix + base32 shape reads better in logs and URLs.
- **Snowflake / sequence ids.** Sortable and compact, but need a coordinated
  generator (a worker-id or a sequence), which a single ULID call does not.
  Revisit only if a per-node monotonic guarantee is ever required.

## Why

A prefixed, sortable id earns its keep three ways: the prefix tells you what a
bare id is (in a log, a URL, an error) and lets a secret scanner recognise a
leaked key; the timestamp ordering gives creation-time sorting and pagination
for free and clusters ids by time for index locality; and both come from one
local call with no coordination. The identifier/secret split is the load-
bearing judgement — the instinct to "make all ids consistent" would have made
credentials sortable, which trades away exactly the entropy and time-privacy a
credential needs. Consistency is in the *prefix* (everything has one); only
identifiers are *sortable*.

Users and devices keep their natural keys — `(tenant, username)` and
`handle + device number` — rather than gaining opaque ids they do not need; an
opaque id is added only where a concept is referenced without a natural key.

## What would reopen this

- **A second concept in another crate needs an id.** `id::prefixed` lifts from
  `tacenta-accounts` into a small shared crate (or `tacenta-wire`-adjacent
  home) so the convention is one implementation, not two.
- **A monotonic guarantee within a millisecond.** ULID's random tail means two
  ids minted in the same millisecond order randomly; if strict
  within-ms monotonicity is ever needed, ULID's monotonic mode (increment the
  random field) is the additive change.
- **Extracting the timestamp.** The creation time is recoverable from the id;
  a decoder (`timestamp_ms`) is a small addition when something needs it.
