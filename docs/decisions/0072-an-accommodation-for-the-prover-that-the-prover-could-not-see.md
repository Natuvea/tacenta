# 0072 — an accommodation for the prover that the prover could not see

## Decision

**A change made to satisfy the verification toolchain is a change, and it gets
reviewed as one.** It does not inherit the assurance of the proof it was made
for. Where such a change alters control flow, the question to ask is what the
new shape does on inputs the old one rejected early — because that is the
class of behaviour the proofs are structurally unable to observe.

## The shape of the class

`tacenta-erasure`, `tacenta-ratchet`, and `tacenta-spqr` each decode a
count-prefixed collection. Written the obvious way, each loop returns early when
an entry cannot be read:

```rust
for _ in 0..count {
    let Some(entry) = decode_entry(bytes, pos) else {
        return Err(DecodeError::Malformed);
    };
    // ...
}
```

Aeneas does not accept it: *"Early returns inside of loops are not supported
yet."* The shape that translates removes the early exit and accumulates a flag:

```rust
for _ in 0..count {
    match decode_entry(bytes, pos) {
        Some(entry) => { /* ... */ }
        None => { ok = false; }
    }
}
if !ok { return Err(DecodeError::Malformed); }
```

Every iteration stays bounds-checked, so nothing panics, and the accepted inputs
are identical. **What changes is how long a rejected input takes.** `count` is
attacker-chosen bytes. An input declaring a count near `u32::MAX` runs the
loop that many times to reach a conclusion the first iteration could have
reached. The accept set is unchanged; the cost of the reject set is not.

## Why the proofs do not see it

Each instrument looking at such a decoder is looking somewhere else.

- **T1 (panic-freedom)** is a statement about what the function *cannot do*,
  not about what it costs. A function that runs for an hour and returns `Err`
  satisfies it exactly as well as one that returns immediately. This is not a
  gap in the proof; it is the proof's scope, and the scope is stated.
- **T3 (refinement)** says which inputs are accepted and what they decode to,
  and that answer does not change.
- **Property tests** generate from a declared shape, and nothing in the shape
  pushes a length field toward `u32::MAX`; they would not notice the duration
  if it did.
- **Review of the diff** is where the class is caught or missed. A commit that
  records the Aeneas constraint and the workaround, correctly, reads as a
  translation detail unless the reader treats it as a control-flow change on
  attacker input. The change is *labelled* as being for the prover, and that
  label is what makes it read as safe.

The last one is why this is a record rather than a code comment.

## The general shape

Verification tooling has a subset it accepts. When code must be rewritten to
enter that subset, the rewrite is driven by what the tool can translate, not by
what the code should do. Those two agree most of the time, and the times they do
not are exactly the times nobody is looking, because the change is filed under
"toolchain" rather than under "behaviour".

The asymmetry that makes this dangerous: **the proofs cannot see the property
that was lost.** Termination-in-reasonable-time is not what T1 or T3 says, so a
green proof after such a rewrite is not evidence the rewrite was harmless. It is
evidence about a different question.

More of these are coming. tacenta-core's upstream findings
(`tacenta-proofs/upstream/README.md` in that repository) list the constraints
the translation imposes — no `?` operator, opaque iterator adapters, `get_mut`
write-back — and each one that forces a rewrite is another instance of this
class.

## What this requires

1. **A commit that rewrites code to satisfy Charon or Aeneas says so in its
   message and says what the rewrite costs**, in the same way a commit that
   changes an algorithm's complexity would. "Aeneas rejected the obvious form"
   is the beginning of the justification, not the end of it.
2. **Coverage-guided fuzzing covers every decoder and state machine.**
   `tacenta-core/fuzz/` carries the targets, running per push as a regression
   gate plus nightly as a search. Fuzzing is the instrument for this class
   because it measures the thing the proofs do not: what an input costs, not
   only what it yields.
3. **The upstream findings carry the consequence**, not only the constraint. A
   findings log that records "Aeneas refuses this shape" without recording "and
   the shape that replaced it does *this*" teaches the next person the
   workaround and not the risk.

## What this does not change

**Not an argument against the verification.** The proofs are worth what they
claim and the claim is accurate. Nor is it an argument for fighting the
translation: the flag-accumulating rewrite is the right response to the
constraint, and the defence against its cost is a one-line bound, not a
redesign.

It is an argument against one specific inference — that a change made for the
prover is a change the prover has checked. It has not, and it cannot.

## The bound, for the record

Each count-prefixed decoder bounds the count against the buffer before the
loop:

```rust
if count > bytes.len() / STRIDE {
    return Err(DecodeError::Malformed);
}
```

This rejects nothing the decoder otherwise accepts — the exact `pos ==
bytes.len()` check at the end already requires the count to account for the
buffer — so it is behaviour-preserving on the accept set and merely prompt on
the reject set.

It divides the whole buffer rather than what remains after `pos`, which is the
looser of the two available bounds. That is deliberate: `bytes.len() - pos`
would introduce a subtraction inside a T1-proved function, and a new panic site
in the verified zone is a worse trade than a bound that admits a few impossible
counts one iteration longer.

Regression tests pin the bound with a maximal declared count, so whoever
changes these decoders next has the input rather than a description of it.
