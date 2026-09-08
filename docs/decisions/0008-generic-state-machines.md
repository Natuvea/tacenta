# 0008 — state machines are generic, in a dependency-free crate

## Decision

The delivery state machines live in `tacenta-state`, generic over the
message type `T`, with zero dependencies. `tacenta-core` instantiates
them at its envelope type via type aliases. The Charon/Aeneas pipeline
translates `tacenta-state` as a standalone crate.

## Considered

- **Keeping them in `tacenta-core`.** The translation would then pull
  the whole dependency tree — including the protocol library — through
  Charon, which is neither feasible nor meaningful.
- **A concrete (envelope-typed) state crate depending on
  `tacenta-wire`.** Translatable, but the translated log entries would
  be a second translated envelope type, and every refinement statement
  would drag an envelope-abstraction through it.

## Why

Genericity does double duty. It keeps the verified zone dependency-free
(the translation covers exactly the code we claim things about), and —
the elegant part — the translated operations are polymorphic in Lean,
so the refinement proofs instantiate them **directly at the
specification's own envelope type**. The abstraction function collapses
to field projection, and the proofs shrink accordingly.

## What would reopen this

- State-machine logic that genuinely needs to inspect message contents
  — that logic would belong in the spec first, and the type parameter
  would grow an interface.
