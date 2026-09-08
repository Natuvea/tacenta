# 0061 — the verified core: a second non-negotiable principle

## Decision

**All security-critical state transitions are specified in Lean and implemented
in an Aeneas-translatable Rust core, with machine-checked refinement between
them. Everything outside that core is an explicit trusted boundary.**

Non-negotiable in the sense that matters: a change that cannot meet it either
moves outside the core with a boundary written down, or does not land.

The mission in tacenta-core's README says what the engine is for. This says what
makes it provable, and the mission alone does not.

## The four layers, and why all four

1. **Lean security model.** Authentication, forward secrecy, rollback, bounds,
   state-transition invariants.
2. **Verification-shaped Rust.** Small leaf crates: total functions, checked
   arithmetic, explicit errors, candidate-state transitions.
3. **Aeneas translation of the shipping Rust**, not a parallel reference
   implementation written to be translatable.
4. **Refinement proofs** that the translated Rust implements the Lean model.

Layer 4 is what makes the other three worth anything. **Lean proofs without it
do not prove the code; Aeneas translation without security theorems proves only
local behaviour.** The two halves are separate deliverables and are never
described as one thing.

## What the core avoids

Panics and unchecked arithmetic. `unsafe`, async, interior mutability. Complex
traits, closures, dynamic dispatch. Hidden mutation and implicit commits.
Generated protobuf types. Unbounded collections and attacker-controlled
allocation. Any control flow the pinned Aeneas toolchain does not support.

## The proof-shaped interface

```rust
fn receive(
    state: &State,
    message: &Message,
) -> Result<(CandidateState, MessageKey), Error>
```

Authentication and durable commit happen outside it. **This makes rollback a
structural property rather than a convention**: a convention is written down
and depends on every caller honouring it; a candidate state that is adopted
only on success depends on nothing.

## The current scope of the principle

Stated plainly, because a principle whose current scope is unlisted is an
aspiration.

**Two receive paths are not yet proof-shaped.** `tacenta-ratchet::receive` and
`tacenta-spqr::State::receive` take `&mut`. They are safe because every caller
clones first, and `tacenta-core/AUTHENTICATION-BOUNDARY.md` records that as a
property of the callers. Under this principle that is a boundary to close
rather than a caveat to document: the whole point is that safety stops
depending on who calls.

**The translation pipeline runs nightly and on a path filter.** Under this
principle, fresh translation and every refinement proof run on every change
that could affect them, as a required check.

**Serialization is outside the verified core.** Nothing is proved from wire
bytes, which is exactly the gap the protobuf decision below turns on.

**The session orchestration is outside the core entirely.** That is the shape
of the current boundary and it is where the next tier of work belongs.

## The protobuf fork, and its consequence for claims

Two branches, and they differ in what may be said afterwards:

1. **Implement a small bounded protobuf subset in Aeneas-compatible Rust**, and
   prove its accepted-input and raw-byte authentication properties. Expensive,
   and it keeps the refinement claim reaching the wire.
2. **Leave generated or unverified protobuf outside the core.** Cheaper, and
   then **serialization and parsing are part of the trusted computing base, and
   no end-to-end refinement from wire bytes may be claimed.**

Either is defensible. What is not defensible is taking the second and describing
the result as the first. Whichever is chosen goes in
`tacenta-proofs/LIMITATIONS.md` and the claim ledger before the code lands, not
after.

## What Lean and Aeneas will not give us

Contracts are required, explicitly and in writing, for: cryptographic
primitives, randomness, storage atomicity, zeroization, and constant-time
behaviour. **None of these follows from a refinement proof.** A model that
assumes an unforgeable MAC proves nothing about the MAC, and a proof about a
state machine says nothing about whether its secrets were erased or how long a
comparison took.

`tacenta-proofs/LIMITATIONS.md` carries these in prose. Prose is the starting
form of a contract, not its final one.

## The compact form

> Small stable API; byte-compatible wire boundary; Aeneas-translatable security
> core; Lean specification and refinement; explicit trusted boundaries; no
> security claim beyond the proved scope.

The last clause is the one that binds hardest.

## What would reopen this

- A security-critical transition that genuinely cannot be expressed in the
  translatable subset. That is a real possibility and the answer is a recorded
  boundary, not a quiet exception.
- The cost of layer 3 on every change outgrowing its value. The measure is
  whether required CI stays green and fast enough to be left required, rather
  than whether anyone finds it annoying.
