# 0077 — the blob is the persistence contract, and durable writing is a utility

## Context

We have two persistence designs. One ships and one cannot.

**The blob model ships.** `Client::export_state` returns the identity, prekeys
and every live session as bytes; `connect_with_state` and `sign_in_with_state`
take them back. The caller decides where the bytes live. The FFI carries all
three, so Swift and Kotlin callers have it too.

**The directory model has no shipping caller.** `DurableOpenParty` wraps
`OpenParty` with a directory it rewrites after every mutating call: temp-write,
`fsync`, `rename`, and an `fsync` of the containing directory. It has
crash-injection tests. It has no non-test caller, and **the type cannot be
given to a `Client` at all.** `Client<P>` requires `P: CryptoProvider`, and
`DurableOpenParty` does not implement that trait. The module says why, and the
reasoning is sound:

> Deliberately not a `CryptoProvider` itself: that trait's `generate`/
> `from_identity` have no room for a directory argument, and a durable store is
> a concrete deployment choice about one provider, not another interchangeable
> provider the conformance oracle should compare `Party` against. **A real
> caller uses this type directly.**

The last sentence describes a caller that does not exist. A caller can only
use it directly by abandoning `Client` and driving the provider itself, which
no shipping path does and no SDK user would.

**So the shape of the problem**: careful crash-atomic storage sits behind a
type the SDK's own client cannot construct, while the blob path, on its own,
leaves the caller to write the bytes however they like — very likely
`fs::write`, which can tear and is not durable on return.

## What was considered

**A. Blob only; delete the durable store.** Honest and simple. Rejected: it
throws away the one piece of code in either repository that gets crash-atomic
writing right, and leaves every caller to rediscover temp-write-fsync-rename,
which most will not.

**B. Change `CryptoProvider` so a durable provider can be constructed.** Add a
configuration parameter to `generate`/`from_identity`. Rejected for now: that
trait is the provider seam kept deliberately narrow, and widening a seam
to carry a deployment concern is how seams stop being seams. It also makes the
conformance oracle compare providers that are no longer interchangeable.

**C. Keep both, and make the durable type reachable.** Re-export it, document
it, add `connect_with_dir`. Rejected as the primary answer: it leaves two
persistence stories in the product and makes the caller choose, when the
difference between them is not one a caller is equipped to judge.

**D. The blob is the contract; durable writing is a utility.** Adopted.

## Decision

**The blob is the persistence contract.** `export_state` /
`connect_with_state` / `sign_in_with_state` are how state is persisted, in Rust
and through the bindings. This is what ships and what documentation describes.

**Durable writing becomes a public utility rather than a property of a provider
nobody can construct.** The temp-write, `fsync`, `rename`, `fsync`-the-directory
sequence is the valuable part of `DurableOpenParty`, and it is orthogonal to
which provider produced the bytes. Exposed as a function over a path and a byte
slice, it serves the blob model directly: the caller keeps ownership of where
state lives, and stops having to get the write right themselves.

**`DurableOpenParty` stays, demoted and labelled.** It is the reference
integration and the fault-injection harness, and its tests are the evidence that
the write sequence is correct. Its documentation must say it is not on a
shipping path, so the next reader does not assume from its existence that
something uses it.

**Anti-rollback attaches to the blob and the utility, not to the
provider.** This is the part of the decision that matters most for what comes
next. A state MAC, generation counter or monotonic anchor has to live where the
bytes are written, and that is the utility, for every caller — not inside one
provider on no shipping path.

## Consequences

- One persistence story in the product, not two.
- The FFI's `exportState` documentation already carries the warning this implies:
  the blob is not a backup, and restoring an older copy rewinds ratchets.
  Under this decision that warning becomes a contract term rather than a note.
- `DurableOpenParty` keeps earning its place as a test fixture while being
  explicitly off the shipping path. If that stops being true — if it goes a
  release without either being used or being exercised — it should be deleted
  rather than left to imply an integration that does not exist.
- The provider seam stays as narrow as it is.

## What would reopen this

- **A caller who genuinely cannot hold the bytes.** If an embedded or
  constrained client needs the library to own its own file, option B becomes the
  question again, and it should be reopened as a change to the seam rather than
  smuggled in as a second provider.
- **Anti-rollback proving impossible at the utility layer.** If the anchor turns
  out to need provider state to be meaningful, the layering above is wrong and
  this record is what gets revisited first.

## Why this is decided rather than proposed

This record is not provisional, and the reason is that **the commitment was
already made and not by this record.**

`export_state`, `connect_with_state` and `sign_in_with_state` ship in the Rust
client under decision 0051, and through the FFI. That published surface is what
obliges a caller to own their state file. This record did not create the
obligation; it names the model that ships and puts the write helper somewhere
reachable.

Marking it provisional would imply a choice is open that the API already closed.
What remains genuinely open is whether to *also* offer a library-owned-file mode
later, and that is recorded above under what would reopen this, as a change to
the seam rather than a second provider.

## Status

**Implemented.** `crates/tacenta-core/src/persist.rs` carries
`write_atomically` over a path and a slice; `DurableOpenParty` uses it rather
than owning it, and its documentation says outright that it is not on a
shipping path and should be deleted if it ever stops being either used or
exercised.

