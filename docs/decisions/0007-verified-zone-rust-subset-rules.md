# 0007 — verified-zone Rust subset: no `?`, no fallible capacity math

## Decision

Two style rules for `tacenta-wire` (and any future crate in the
verified zone), both required to prove `encode`:

1. **`let`-`else` instead of the `?` operator.** `?` desugars through
   the `Try` trait, which the Aeneas translation can only represent as
   opaque axioms — and axioms end every proof. Plain matches translate
   to fully definable Lean. Enforced by a crate-level
   `#![allow(clippy::question_mark)]` with the reasoning attached.
2. **Capacity arithmetic must be infallible.** A
   `Vec::with_capacity(HEADER_LEN + payload.len())` contains a checked
   add that the model exposes as a genuine panic path (32-bit `usize`,
   near-`u32::MAX` payload). Capacity is an optimization, so it has no
   business being able to panic: `saturating_add`.

## Considered

- **Keeping `?` and axiomatizing the `Try` externals by hand** (the
  `-split-files` route). Workable, but every hand-written axiom is
  trusted-surface the proofs silently rest on; a syntactic rule that
  keeps the translation axiom-free is strictly stronger.
- **Dismissing the capacity overflow as unreachable.** It very nearly
  is — but "nearly, argued in a comment" is exactly the kind of claim
  this project exists to replace with theorems, and the rule costs one
  word.

## Why

The refinement theorem (`Verification.encode.spec`) states
panic-freedom unconditionally-up-to-address-space. Both rules exist to
make that theorem both provable and honest: no axioms smuggled in by
sugar, no panic paths waved away by informal argument.

## What would reopen this

- Aeneas gaining native `Try`-trait support — rule 1 becomes obsolete.
- A verified-zone function that genuinely needs fallible arithmetic —
  that fallibility then belongs in the function's `Option`/`Result`
  contract, never in a panic.
