# Reproducing the assurance

One place that says, from a clean checkout, how to rebuild every proof, run
every test, and see the axiom baselines — so a reviewer reaches green without
reverse-engineering CI. The public `.github/workflows/ci.yml` here runs the
commands below that need no pinned prover toolchain (fmt, clippy, the Rust
suite, the spec build, and the committed-vector check); the axiom-pinned
refinement build and the Postgres integration run in the verification workflow
and the release pipeline. This page is the single
ordered recipe for all of it, and the workflows remain the source of truth
where they overlap.

There are two repositories, and the assurance is split across them on purpose:

- **`tacenta`** (this repo) — the product. Machine-checked proofs cover the wire
  format, the delivery state machines, and the directory trust core. It writes no
  cryptography.
- **`tacenta-core`** (sibling repo, pinned by 40-char revision in `Cargo.toml`) —
  the cryptographic core: the Double Ratchet, the sparse post-quantum ratchet, the
  ML-KEM braid, and the composed triple ratchet, with their own proofs on their
  own axiom baseline. Read its `tacenta-proofs/CLAIMS.md` and `LIMITATIONS.md`.

Read alongside [claims.md](claims.md) (proven vs tested vs assumed),
[verification-tcb.md](verification-tcb.md) (what a green proof depends on).

## Prerequisites

- **Lean 4 via elan**, toolchain `v4.31.0` (`lake` on PATH). The lake projects
  pin it; elan installs the pinned toolchain on first `lake build`.
- **Rust stable** (`cargo`, `clippy`, `rustfmt`).
- **`protoc`** (protobuf compiler) and **`python3`**.
- `tacenta-core` at the pinned revision (a public repository) — cargo resolves
  it as a git dependency. Check it out as a sibling directory, or let cargo
  fetch it.

Toolchain pins (decision 0006): Lean 4 `v4.31.0`, Charon/Aeneas nightly
`2026.07.22` (the latter only for the retranslation below, not the every-push
proof build).

## 1. The cryptographic core — `tacenta-core`

One gate builds the Lean model and proofs (no `sorry`), checks the attestation
manifests against the proofs, regenerates and diffs the model vectors, and runs
every Rust crate (fmt, clippy, tests, and the property-based decoder tests):

```bash
cd tacenta-core
bash tooling/ci.sh
```

The heavier Aeneas retranslation is deliberately **not** in that gate; it runs
in tacenta-core's verification workflow, while the committed
translation's T1/T3 proofs build in tacenta-core's public `translation` CI job
(`tacenta-proofs/scripts/no-sorry.sh`).

## 2. The product proofs — `tacenta/spec` and `tacenta/verification`

`spec/` holds the hand-written specification and the spec-level theorems;
`verification/` holds the theorems that carry "the shipped Rust, not a model of
it" via the committed Aeneas translation.

```bash
# Spec-level theorems (no sorry), plus the #print axioms audit in
# spec/Tacenta/Assurance.lean that pins each theorem's exact axiom set.
cd tacenta/spec && lake build

# Conformance vectors are extracted from the spec and must match contracts/.
lake exe vectors envelope | diff -u ../contracts/vectors/envelope-v1.json -
lake exe vectors session  | diff -u ../contracts/vectors/session-v1.json  -
lake exe vectors user     | diff -u ../contracts/vectors/user-v1.json     -
lake exe vectors stream   | diff -u ../contracts/vectors/stream-v1.json   -

# Refinement theorems over the committed translation of the shipped Rust.
cd ../verification && lake exe cache get && lake build
```

Regenerating the Aeneas/Charon translation itself (heavier, needs the pinned
Charon/Aeneas) is `tooling/run-aeneas.sh`; the every-push path above builds the
committed translation rather than re-deriving it.

## 3. The product Rust

```bash
cd tacenta
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# The Postgres store is behind a feature; compile-check it (its integration
# tests need a database -- see the note below).
cargo clippy -p tacenta-accounts -p tacenta-server --features "tacenta-server/postgres" --all-targets -- -D warnings
```

## 4. The repo gates

```bash
cd tacenta
for s in tooling/check-*.sh; do echo "== $s =="; bash "$s"; done
# check-docs-match.sh resolves citations across both trees, so point it at a
# checkout of tacenta-core at the pinned revision:
TACENTA_CORE_DIR=/path/to/tacenta-core bash tooling/check-docs-match.sh
```

## The axiom baselines (what a green proof rests on)

- **Spec-level theorems** admit no axiom beyond `propext`, machine-enforced by
  `#guard_msgs in #print axioms` in `spec/Tacenta/Assurance.lean` — a corrupted
  axiom set fails the build.
- **Refinement theorems** (`verification/`) sit at Lean's three classical axioms
  plus one per-declaration `bv_decide` reflection axiom for each of two
  byte-order lemmas (see `docs/claims.md`); their pinned
  set is machine-enforced in `verification/Verification/Assurance.lean` (mirrors
  the spec audit).
- **tacenta-core** carries its own baseline; see its `tacenta-proofs`.

## What the every-push path does NOT reproduce (stated, not hidden)

- The Aeneas/Charon retranslation (`tooling/run-aeneas.sh`, and tacenta-core's
  verification workflow) — heavier, pinned toolchain, run on demand.
- **Postgres-backed integration tests** — the *local default* here (step 3's
  `cargo test --workspace`) skips them: they sit behind the `postgres` feature
  and return early without `TACENTA_TEST_DATABASE_URL`. To run them locally, set
  that to a reachable database and run `cargo test -p tacenta-accounts
  -p tacenta-server --features "tacenta-server/postgres"`. The public
  `.github/workflows/ci.yml` in this repository does **not** run them; the release pipeline stands up a
  `postgres:16` service container and runs them there.
- Timing-sensitive tests and the sustained-flood tests are `#[ignore]`d /
  skipped from the broad run; run them by name when profiling.
