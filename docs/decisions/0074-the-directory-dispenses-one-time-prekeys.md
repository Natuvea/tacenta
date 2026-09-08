# 0074 — the directory dispenses one-time prekeys

## Decision

**The directory becomes a stateful dispenser of one-time prekeys.** A device
uploads a pool of one-time bundles alongside its multi-use one; each lookup
removes one from the pool and serves it; when the pool is empty the multi-use
bundle is served instead, which is the sound fallback the protocol already
relies on.

This is the record decision 0050 said this "deserves". 0050 chose to publish no
one-time prekey at all rather than serve the same one to everybody, and called
directory dispensing "correct, and where this ends up".

## The problem a dispenser solves

A stored bundle that carries a one-time prekey is served to every requester
until the first authenticated use, so a stateless directory hands the same
"one-time" identifier to everyone who fetches in that window. The consequences
run in both directions:

- **Legitimate messages fail.** The first initial message to arrive consumes
  the prekey. Every other peer holding that bundle sends a message naming an
  identifier the store no longer has, and gets `UnknownPrekeyId`.
- **The property the key exists for does not hold.** A one-time prekey is
  supposed to be used once. Served repeatedly, it is a shared secret among
  everyone who fetched the bundle in that window.

What a stateless directory lacks is an *allocation protocol*: an inventory
contract, and an owner for the question of who is allowed to hand out which
identifier.

## Why the directory, and why that is allowed

In a real deployment the server allocates each public one-time prekey exactly
once while the client retains the private half until an authenticated message
uses it. There is no way to get that from the client alone: the client is not
present when a peer fetches its bundle, and two peers fetching concurrently is
the normal case rather than the edge one.

**This does not touch decision 0012.** That decision makes the *relay*
cryptographically blind and enforces it through the dependency graph. The
relay is not involved here. The directory is a different component and has
always held published public material.

**It does amend decision 0018**, which describes the directory as "a lookup
from a device to its published *public* material". It stays exactly that in the
sense that matters — everything it holds is public, and it still cannot read a
message — but it stops being stateless. A lookup now has an effect. That is a
real change to the component's character and is the reason this needs a record
rather than a commit.

## What it does not change

- **No private key moves.** Everything pooled is public bundle material. The
  private halves never leave the client, and deletion on authenticated use
  stays exactly where it is.
- **Exhaustion is not an error.** A bundle served without a one-time prekey is
  sound; the signed prekey and the KEM prekey are multi-use by design, which is
  what makes 0050's fallback correct. Running out degrades forward secrecy
  slightly; it does not break session establishment.
- **The last-resort replay record stays.** It guards the reusable KEM key,
  which this does not remove. Dispensing makes that path rarer, which is what
  keeps the record's 1024-entry bound generous, but it does not replace it.

## Why the pool holds whole bundles

A pool of bare one-time prekeys, with each lookup serving one *alongside* the
stored bundle, would mean the directory parsing a bundle and rebuilding it with
a prekey spliced in, and the directory holds opaque bytes precisely so it
cannot do that (decision 0018).

**The pool holds complete bundles instead**, each carrying a one-time prekey no
other entry carries. A lookup pops one whole bundle. Three things follow, all
of them better:

- The directory never looks inside a cryptographic blob, so 0018's character
  survives the change in every sense except statelessness.
- It works for any bundle format without knowing what it holds.
- It dispenses the one-time *curve* prekey and the one-time *KEM* prekey
  together. tacenta-core has both, and a pool of bare prekeys would have needed
  to special-case that; a pool of bundles gets it for free.

The cost is repetition: each pooled bundle repeats the signed prekey and the
KEM prekey, so a pool of thirty-two costs roughly fifty kilobytes per device.
That is a directory holding more bytes, which is the cheap side of the trade.

## The contract

1. **Upload.** A device publishes its multi-use bundle and a batch of complete
   one-time bundles, each carrying a distinct one-time prekey. Identifiers are
   the client's, drawn from `PrekeyStore::next_id`, so the directory never
   invents one and never reads one.
2. **Dispense.** A lookup pops one bundle from the pool atomically. Two
   concurrent lookups get different bundles, or one gets the fallback; neither
   may get the same one-time prekey.
3. **Exhaustion.** An empty pool serves the bundle without a one-time prekey.
4. **Replenish.** A device tops its pool up when it observes it running low.
   `PrekeyStore::replenish` already produces the keys and continues the
   identifier sequence.
5. **Rotation.** Re-registering a bundle replaces the pool; identifiers from a
   superseded pool are not reused, which `next_id` already guarantees.

**The atomicity in step 2 is the whole decision.** A dispenser that reads then
writes without a transaction serves duplicates under concurrency, which is the
duplication this decision exists to prevent, wearing a server hat.

## Cost, stated rather than discovered

- `tacenta-directory` gains per-device state and a mutating lookup, and the pop
  must be atomic. The directory is in memory with file-snapshot persistence;
  Postgres backs `tacenta-accounts` and nothing else. The atomicity therefore
  comes from `&mut self` plus the mutex the server already holds. If the
  directory is ever moved to a database, the pop must be a single statement.
- The directory protocol grows a deposit request carrying a batch of bundles.
  The bundle-fetch response does not change shape at all, which is a further
  dividend of pooling whole bundles. This is *our* directory protocol, not the
  message layer, so bundle-layer compatibility does not apply and no interoperability claim
  is at stake.
- `PrekeyStore::publish` splits: the client still needs a bundle-without-pool
  for the fallback path, and a way to emit a batch for upload.
- Tests must include the concurrent case. A dispenser that is correct
  single-threaded and duplicates under load has not fixed anything.

## Status

**Implemented.** Every element of the contract above exists and is tested end
to end over a real socket (`tacenta-server/tests/prekey_dispensing.rs`):
dispensing once each, falling back when the pool empties, refusing a deposit
from anyone but the bound device, refusing a forged possession proof, and
clearing a stale pool when the bundle is re-registered.

The client stocks its pool immediately after registering, and **a failure there
is deliberately not a connection failure**. Without a pool the directory serves
the multi-use bundle to everyone, which is sound and costs only the extra
forward secrecy a one-time key would have added; refusing to connect over it
would trade a working session for a stronger one that is not available.

**One behaviour to carry forward.** `publish_bundle` returns the multi-use
bundle without a one-time prekey. A bundle served repeatedly must not carry
one, which is decision 0050's position and this record's premise. One-time
prekeys travel in the batch and are handed out singly.
