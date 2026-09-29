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
lake exe vectors group    | diff -u ../contracts/vectors/group-v1.json    -

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

## 4. The bounded group experiment

The experiment is limited to eight members, one device per person and one
membership authority, and no SDK head reaches it; `docs/claims.md` says what it
does and does not establish. Run the group crate's limit and negative-control
suites, the group crate changes the coordinator needs, and the live
bounded-profile traces. The traces cover cap-plus-one refusals, group and
direct-message session sharing, prepared-handoff cancellation on removal, a
member removed while a message is in flight (authority and recipient side),
replay after a restore, the dedup window, the future queue and the outbox
limits, the ninth member on the roster, invitation and admission paths,
invitation admission and removal, and revocation. The `GroupClient` traces run
through a real provider, relay and directory:

```bash
cd tacenta
tooling/run-group-chat-demo.sh
```

`tooling/group-chat-demo-tests.txt` lists, for each step, the exact names of the
tests it must run (with the test binary they belong to) and pins the count. The
script fails a step that exits non-zero, runs zero tests, fails or ignores a
test, prints a test line that says `should panic`, or whose set of passing test
names or count differs from that manifest; it prints each missing and each
unexpected test. A green run therefore means that the named tests exist, ran
and passed, and that their names and counts equal the manifest. It does not
mean that a test still checks what its name says: a test whose body returns
early, asserts `true`, asserts inside a task nobody awaits, or is empty, but
keeps a listed name, passes. Review is what looks at bodies, and for the group
crate the mutation harness below. CI does not run this script.

After a deliberate change to the tests, run
`tooling/run-group-chat-demo.sh --update-manifest` and review the manifest's
diff in the same commit. That mode is never implied, it still requires every
step to pass, and its run compares nothing with the old manifest.

The Lean group model generates the trace vectors that the Rust types replay
(`crates/tacenta-group/tests/model_vectors.rs`); CI regenerates and diffs them
with the other vector sets:

```bash
(cd spec && lake exe vectors group) | diff -u contracts/vectors/group-v1.json -
```

To capture comparable cold and warm process-level measurements, pass an output
directory. The runner records the product revision, the tacenta-core revision
that `Cargo.lock` resolves, whether the tree had uncommitted changes, the host,
the Rust toolchain and the load average; the demo's logs and its elapsed, user,
system and maximum-resident figures, cold and warm; the deterministic 2, 3 and
8 member roster and receiver-state sizes (real 32-byte identities: 219, 260 and
465 roster bytes); the three-client native transaction, sender restart and
snapshot figures; and, from the client's per-size probe, run once per size in
its own process and twice, snapshot bytes, provider-state bytes, whole-snapshot
commits per logical send, the time of that send, the median latency of one more
commit at that size, the restart and recovery time, and the probe's CPU and
maximum resident set. A missing measurement, including a missing probe, stops
the runner. The runs are not seeded (keys come from the operating system), and
the results are development evidence, not production budgets or 32, 128 or 512
member results.

One recorded run: the integration branch with a clean tree, tacenta-core
`5a8f90c1`, an Apple M5 Pro with 18 logical CPUs and 64 GiB, `rustc
1.99.0-nightly` (2026-07-14), a load average of about 8.4 from other work on the
machine, native file store, one 1,000-byte logical send from the authority to
every other member. Sizes were identical in the two passes of each size; times
moved by up to about a quarter between passes.

| Members | Roster bytes | Receiver state | Snapshot bytes | Provider state | Commits per logical send | Logical send | One commit at that size (median) | Restart and recover |
|---|---|---|---|---|---|---|---|---|
| 2 | 219 | 343 | 191,542 | 174,236 | 4 | 36 to 38 ms | 6.0 to 7.7 ms | 37 to 40 ms |
| 3 | 260 | 384 | 221,149 | 188,442 | 7 | 68 to 69 ms | 7.9 to 8.0 ms | 39 to 40 ms |
| 8 | 465 | 589 | 371,518 | 259,472 | 22 | 253 to 256 ms | 8.0 to 8.1 ms | 47 to 50 ms |

A logical send costs one commit for the intent and three per recipient (prepare,
reserve, accept), each rewriting the whole snapshot, so the time of a send grows
with the number of recipients times the snapshot size. The probe process's
maximum resident set was 14 MB, 15 to 16 MB and 20 to 23 MB and its user CPU
0.23 s, 0.34 s and 0.95 s at 2, 3 and 8 members. The whole demo in one process:
27 s elapsed (68 s CPU, 657 MB) cold and 9 s (20 s CPU, 96 MB) warm. Nothing was
measured at 32, 128 or 512 members or on another host.

```bash
tooling/measure-group-chat.sh /tmp/tacenta-group-measurements
```

To check that the group crate's tests notice a removed guard, run its
single-change mutation harness (131 mutants; a few minutes with four workers,
longer on a loaded machine). It needs the unmodified tree to pass, prints each
mutant as killed or survived, and fails on a mutant that does not patch or build:

```bash
python3 tooling/group-mutation/mutate.py --workers 4
```

At the revision that added mutants R17 to R21 it killed 124 and left seven
standing, each argued: `L05` (the 4,096-byte roster bound is above the largest
valid roster, 3,048 bytes, so nothing reaches it), `L10` and `S11` (a second
check returns the same error; the pair with both removed, `D10` and `D11`, is
killed), `N13` (the duplicate lookup runs before the sequence-order check),
`N36` (`Roster::validate` already enforces the genesis shape, so every roster
that reaches `accept_source` at revision zero passes the genesis checks),
`P01` (the 8 KiB payload-input bound is an early exit that gives the error the
length check gives) and `X15` (a third reserved attempt already exhausts the
recipient). These are arguments from the code, not proofs of equivalence. The
harness covers the group crate only; the client crate has no harness in this
repository.

## 5. The repo gates

```bash
cd tacenta
for s in tooling/check-*.sh; do echo "== $s =="; bash "$s"; done
# check-docs-match.sh resolves citations across both trees, so point it at a
# checkout of tacenta-core at the pinned revision:
TACENTA_CORE_DIR=/path/to/tacenta-core bash tooling/check-docs-match.sh
```

## The axiom baselines (what a green proof rests on)

- **Spec-level theorems** admit no axiom beyond `propext` and `Quot.sound`
  (the wire theorems and two of the four bounded-group theorems use the second;
  the others need at most `propext`), machine-enforced by
  `#guard_msgs in #print axioms` in `spec/Tacenta/Assurance.lean` — a corrupted
  axiom set fails the build. The four group theorems are in that audit; the
  group model, its vectors and those theorems have had no human review.
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
