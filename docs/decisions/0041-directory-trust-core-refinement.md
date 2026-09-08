# 0041 — refining the directory trust core to the Rust

## Decision

The directory's trust-critical decision — trust on first use for registration,
and the rotation state rule — is extracted into a leaf crate
`tacenta-directory-core` as two pure functions of one device's current binding,
`register_core` and `rotate_core`, and **mechanically refined** to the Lean spec
via Charon/Aeneas, the same pipeline as the wire codec and the delivery machines
(decision record 0006).

Shape:

- **A leaf crate, not a module.** `tacenta-directory-core` has no dependencies
  and no `HashMap` — `register_core(current: Option<Vec<u8>>, presented) ->
  (Registration, Vec<u8>)` and `rotate_core` operate on a single device's
  binding. `tacenta-directory` depends on it, re-exports `Registration` /
  `Rotation`, and its `Directory::register` / `rotate` are glue that read the
  current binding from the `HashMap`, call the core, and store the result plus
  the (trust-irrelevant) prekey bundle and device index. Behaviour is unchanged.
- **Why a `HashMap` cannot be in the core.** Charon/Aeneas translate a pure
  subset of Rust; `std::collections::HashMap` is outside it (the full-crate
  translation of `tacenta-directory` fails on exactly `register` / `rotate` /
  `devices_of`). A `HashMap` carries no trust anyway — the trust is the decision
  about one binding — so isolating that decision into a translatable function is
  both necessary and honest.
- **The spec carries the target.** `spec/Tacenta/Directory.lean` gained
  `registerCore` / `rotateCore` matching the Rust exactly, with
  `registerCore_tofu` etc. proven, and `register_matches_core` proving the
  `HashMap` wrapper's observable binding at a device equals the pure core
  applied — so refining the core suffices for the method.

## Verification

`tooling/run-aeneas.sh` now translates `tacenta-directory-core` alongside the
wire and state crates; the generated
`verification/Verification/Generated/TacentaDirectoryCore.lean` is committed like
the others. `verification/Verification/DirectoryRefinement.lean` proves, against
the Aeneas Lean library:

- `register_core_refines` / `rotate_core_refines` — the translated Rust returns
  `ok` and agrees with the spec's `registerCore` / `rotateCore` under the byte
  abstraction (`absBytes`), including a from-scratch `Vec<u8>` `PartialEq::eq`
  spec (`vec_eq_u8`) since the Aeneas library ships only the slice one.
- `register_core_tofu_translated` — trust on first use on the **shipped** Rust: a
  bound device keeps its binding whatever key is presented.
- `rotate_core_requires_binding_translated` — an unbound device cannot be
  rotated.

The whole `verification/` package builds under CI's `verification` job
(`lake build`); no `sorry`. The proofs use the standard mathlib axiom set
(`propext`, `Classical.choice`, `Quot.sound`) that the existing wire/state
refinements use — heavier than the mathlib-free `spec/` (propext only), because
the refinement layer reasons through the Aeneas library.

## Considered

- **A module inside `tacenta-directory`, gated so Charon sees only it.** Charon
  translates the whole crate; the `HashMap` methods still fail and pollute the
  output with errors, and the generated file is partial and will not build. A
  leaf crate gives Charon a crate with nothing untranslatable in it, so the
  generated file is complete and compiles.
- **Refining `Directory::register` directly (modelling the `HashMap`).** Aeneas
  can model some collections, but the directory also holds the device index and
  bundle, none of which carry trust; modelling them to prove a property about the
  identity binding is effort spent on the wrong thing. The extraction states the
  trust property on exactly the state it concerns.
- **Leaving it at spec-level + differential tests.** The
  conformance tests (`spec_conformance.rs`) are real evidence but cover only the
  traces they draw; the refinement covers all inputs and is the standard the
  formal-methods audience applies. The tests remain, now guarding the wrapper's
  cross-device framing (which the core, being single-device, does not address).

## What would reopen this

- **Extending the refinement to the rest of the authorization logic.** Authorized
  rotation/recovery (the currently-bound key signing the change), the relay's
  per-device authorization, and the account/provisioning authorization are
  spec-proven and written-to-match but not yet refined; each would follow this
  same extract-a-pure-core-then-refine shape.
- **A Charon/Aeneas pin bump** (0006) — the generated file and the proof are
  pinned to the same nightly and move together.
- **The directory gaining a persistent (Postgres) store.** The trust core stays
  the same pure function; only the wrapper changes, and `register_matches_core`
  is what keeps the wrapper honest.
