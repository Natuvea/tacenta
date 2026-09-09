# The trusted computing base of the verification

Tacenta's proofs are only as strong as what you must trust to believe them.
This page states that trusted computing base (TCB) explicitly: what a green
proof depends on, what it covers, what it does **not**, and what would make it
vacuous. A proof whose assumptions are not written down is assurance theatre;
this is the antidote.

Read alongside [claims.md](claims.md) (proven vs tested vs assumed) and the
[threat model](threat-model.md) (what the system defends).

## What is proven

Machine-checked against the specification, no `sorry` anywhere. These
refinement proofs rebuild in the verification workflow, not in the `ci.yml`
in this repository; the specification proofs rebuild in the public `spec` job.
Both reproduce locally (see `reproduce.md`):

- **The v1 wire codec** (`tacenta-wire`): encode/decode round-trip both
  directions, single-envelope and streamed, with wrong version, unknown kind,
  length mismatch, and trailing bytes rejected by construction.
- **The delivery state machines** (`tacenta-state`): the single-device `Session`
  and multi-device `User` machines, and the composed delivery guarantee (a
  message is delivered exactly when every device has acked past it, and stays
  delivered under later appends and acks).
- **The directory trust core** (`tacenta-directory-core`): the trust-on-first-use
  registration decision and the rotation decision (`register_core` /
  `rotate_core`), as pure functions of one device's current binding. The
  translated Rust is proven to refine the spec's `registerCore` / `rotateCore`,
  and trust on first use — a bound device keeps its binding whatever key is
  presented — holds on the translated Rust (`register_core_tofu_translated`).
  The `HashMap`-backed `Directory` that wraps this core is outside the
  translatable subset; the spec's `register_matches_core` proves the wrapper
  applies the core faithfully, so the core carries the wrapper's trust.

The Rust in these crates is translated to Lean by Charon/Aeneas and proven
to **refine** the hand-written Lean specification — so the shipped Rust, not
just a model of it, inherits the theorems. Toolchain pins: Lean 4 v4.31.0,
Charon/Aeneas nightly 2026.07.22 (decision record 0006).

## What you must trust (the TCB)

A green proof depends on every item below. Each is a place a bug or a mistake
could make the proof believe something false.

1. **The Lean 4 kernel.** The proof checker itself. Small, widely scrutinised,
   and the standard root of trust for Lean developments — but it is in the TCB.
2. **Charon.** It reads the Rust and emits an intermediate representation
   (LLBC). We trust that this faithfully models the Rust language semantics; a
   Charon soundness bug could make the translated model diverge from what rustc
   actually runs.
3. **Aeneas.** It turns Charon's output into a pure Lean functional model that
   the proofs reason about. We trust the model corresponds to the borrow-checked
   Rust execution (Aeneas's functional-translation soundness). Charon and Aeneas
   together are the largest, most Tacenta-specific part of the TCB.
4. **The specification is the intended one.** The proofs show the Rust refines
   the Lean spec. If the *spec* does not capture the intended property — a wrong
   wire format, a delivery rule that permits a reorder we did not mean to allow —
   then a green proof is vacuously true of the wrong thing. **The spec is
   human-written and is itself the object to review.** No proof relieves the
   reader of reading the spec.
5. **The absence of `sorry`, and two different axiom baselines.** `sorry` (an
   admitted, unproven goal) is forbidden repo-wide. The axiom position is **not
   uniform across the two halves of this document, and the difference matters**:
   - The **specification-level** trust theorems admit no axiom beyond `propext`
     (propositional extensionality, baked into Lean's logic and not a soundness
     risk). That is **machine-enforced**: `spec/Tacenta/Assurance.lean` pins the
     exact axiom set of each with `#guard_msgs #print axioms`, so a `sorry`
     (which would add `sorryAx`) or any unexpected axiom fails the CI `spec`
     build. The audit is checked to be non-vacuous — corrupting an expected
     axiom set does fail the build.
   - The **refinement** theorems in `verification/` — the ones that carry
     "the shipped Rust, not just a model of it" — sit at Lean's three standard
     classical axioms (`propext`, `Classical.choice`, `Quot.sound`), plus the
     two per-declaration `bv_decide` reflection axioms
     (`Verification.fromBE2_toNat._native.bv_decide.ax_…` and its `fromBE4`
     twin) for two byte-order lemmas -- on Lean v4.31.0 these are what
     `#print axioms` names. That baseline is
     **machine-enforced**: `verification/Verification/Assurance.lean` pins each
     headline refinement theorem's exact axiom set with `#guard_msgs`, built by
     the `verification` workflow (not this repository's `ci.yml`), so a
     `sorry` (which would add `sorryAx`) or an unexpected axiom fails the
     build -- mirroring the spec-level audit in `spec/Tacenta/Assurance.lean`.
     It is also recorded in `docs/claims.md`.
6. **Lean's compiled evaluator, for two lemmas.** `decode.spec` and the round
   trip discharge two byte-order lemmas with `bv_decide` SAT certificates, whose
   checking runs through Lean's compiled evaluator rather than the kernel
   (surfacing as the per-declaration `…_native.bv_decide.ax_…` axioms named
   in item 5). So for those results the evaluator and the certificate
   checker are in the trusted base, not only item 1's kernel. This is the one
   assumption here that *enlarges* the kernel-trust boundary.
7. **The toolchain pins.** Reproducing the proof means the pinned Lean, Charon,
   and Aeneas versions; a different version could accept or reject differently.
   The pins are the reproducibility boundary.

## What the proof does NOT cover

Stating the scope is half the honesty. The proofs say **nothing** about:

- **The compiled artifact.** The theorems are about the Charon/Aeneas model, not
  the machine code rustc produces, the standard library, or LLVM. The decoder
  **fuzz tests** exist precisely to exercise the *compiled* Rust on adversarial
  input, as complementary evidence on the artifact the proof does not reach.
- **The cryptography.** The protocol library is `tacenta-core`, a pinned
  dependency (`DefaultProvider = open::OpenParty`), assumed correct here and
  deliberately not re-proven in this repository; it carries its own proofs on
  its own axiom baseline (see below). Interoperability testing against any
  third-party implementation is confined to a segregated harness outside this
  repository, under tacenta-core's ADR-0003 and ADR-0005, and nothing from it
  is linked into any product build. Using the protocol correctly (session
  establishment, key handling) is our risk and is *tested*, not proven.
- **Most of the authorization logic.** The directory trust *core*
  (trust-on-first-use registration and rotation, `tacenta-directory-core`) is now
  refined to the spec — see above. The rest is spec-proven but not yet refined to
  Rust: the directory's *authorized* rotation and recovery (the currently-bound
  key signing the change), the relay's per-device authorization, and the
  account/provisioning authorization. Those Lean models are proven and the Rust
  is written to match (tested, fuzzed, and differential-conformance-tested), but
  not mechanically refined. Extending the refinement across them is the open
  frontier (planned work), and where a formal reviewer should push next.
- **The transport, the async runtime, concurrency, and timing.** The proofs are
  about pure functional behaviour; TLS, the network, the tokio runtime, and
  side-channels are out of scope of the proof (side-channel reasoning is
  documented separately).
- **`tacenta-core`, entirely.** This repository pins the clean-room protocol
  library (`Cargo.toml`) and CI builds and tests against it, which is easy to
  mistake for coverage. It is not. `tacenta-core` carries its own proofs, its
  own axiom baseline, and its own limitations document, none of which is checked
  here and none of which this page's TCB describes. And
  `tacenta-core` is the provider that actually ships (`DefaultProvider =
  open::OpenParty`, decision record 0075), so its separate, unchecked-here
  verification story is the one carrying the live cryptography -- this page's
  proofs say nothing about it. Read `tacenta-core`'s own `CLAIMS.md` and
  `LIMITATIONS.md` for what is proven there; treat the two verification stories
  as separate.

## What would make a green proof mislead

- Reading "the codec and delivery machines are proven" as "the system is proven".
  It is not — most of the security-relevant logic is not in the proven zone (see
  above and the threat model).
- A specification that does not mean what the reader assumes (item 4).
- A soundness bug in Charon or Aeneas (items 2–3).
- A `sorry` or a smuggled axiom (item 5) — guarded by CI, but named here because
  the guard is part of the TCB too.

## Why state this at all

The audience that matters for this repository is the one whose profession is
catching the gap between a claim and its evidence. To that reader, an
unqualified "verified" is a red flag and a stated TCB is a green one. Tacenta's
proofs are real and use that community's own tools (Aeneas); their value is
exactly bounded by this page, and saying so is the point.
