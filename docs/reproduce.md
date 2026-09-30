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
# Spec-level theorems (CI fails on a `sorry`), plus the #print axioms audit in
# spec/Tacenta/Assurance.lean that pins the exact axiom set of the 47 theorems
# it lists (see "The axiom baselines" below for what it does not cover).
cd tacenta/spec && lake build

# Conformance vectors are extracted from the spec and must match contracts/.
lake exe vectors envelope | diff -u ../contracts/vectors/envelope-v1.json -
lake exe vectors session  | diff -u ../contracts/vectors/session-v1.json  -
lake exe vectors user     | diff -u ../contracts/vectors/user-v1.json     -
lake exe vectors stream   | diff -u ../contracts/vectors/stream-v1.json   -
lake exe vectors group    | diff -u ../contracts/vectors/group-v1.json    -

# The group wire formats have no Lean model, so their byte vectors are written by a
# Rust test (decision 0149) and replayed by a second program, a differential oracle
# first written from spec/group-wire-formats.md and the vectors (it is not an
# independent implementation). The first command fails if the committed file differs
# from the test's builder; the second replays every vector through the second program.
cargo test --locked -p tacenta-group --test group_wire_vectors
bash ../tooling/check-group-wire-vectors.sh

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

The byte layouts of the peer-exchanged group formats are specified in
`spec/group-wire-formats.md`. Their vectors, `contracts/vectors/group-wire-v1.json`,
are not generated from the model: `crates/tacenta-group/tests/group_wire_vectors.rs`
builds them from the page and replays them against the Rust codecs, and
`tooling/group_wire_reference.py`, a differential oracle that a separate agent first
wrote from the page and the vector file and that was edited afterwards, replays them
too (`bash tooling/check-group-wire-vectors.sh`, which CI runs). After a deliberate
change to a layout, rewrite the file with
`TACENTA_WRITE_GROUP_WIRE_VECTORS=1 cargo test -p tacenta-group --test group_wire_vectors`
and review the diff. A single-change mutation run over these codecs is
`python3 tooling/group-mutation/mutate.py --mutants wire_mutants.py`.

To capture comparable cold and warm process-level measurements, pass an output
directory. The runner records the product revision, the tacenta-core revision
that `Cargo.lock` resolves, whether the tree had uncommitted changes, the host,
the Rust toolchain and the load average; the demo's logs and its elapsed, user,
system and maximum-resident figures, cold and warm; the deterministic 2, 3 and
8 member roster and receiver-state sizes (real 32-byte identities: 219, 260 and
465 roster bytes); the three-client native transaction, sender restart and
snapshot figures; from the client's per-size probe, run once per size in its own
process and twice, snapshot bytes, provider-state bytes, whole-snapshot commits
per logical send, the time of that send, the median latency of one more commit
at that size, the restart and recovery time, and the probe's CPU and maximum
resident set; and, from a second probe, the same eight-member group after
seventeen sends (below). A missing measurement, including a missing probe,
stops the runner, and it asserts the values that do not depend on the machine
(the roster and receiver-state bytes, and 4, 7, 22 and, in steady state, 22
commits per logical send); times and snapshot bytes are reported, not asserted.
The runs are not seeded (keys come from the operating system), and the results
are development evidence, not production budgets or 32, 128 or 512 member
results.

**The per-size table is one send from an empty outbox, and a group in use is
larger and slower.** The recorded run: this branch at `f26b56f` with a clean
tree, tacenta-core `5a8f90c1`, an Apple M5 Pro with 18 logical CPUs and 64 GiB,
`rustc 1.99.0-nightly` (2026-07-14), native file store, one 1,000-byte logical
send from the authority to every other member, **on a machine that other work
kept busy: a load average of 15.4 when the runner started** (31.6 and 40.5 over
the previous five and fifteen minutes). Sizes were identical in the two passes of
each size; times were within about 3 to 8 percent between passes. The times move
with the load, and these are not the fastest this code has run: a run of the
previous revision at a load of about 1 gave 502 to 510 ms for the last send in
steady state, and one at a load of 4 to 5 gave 515 to 517 ms. Read the times as
indicative and the bytes and commit counts as exact.

| Members | Roster bytes | Receiver state | Snapshot bytes | Provider state | Commits per logical send | Logical send | One commit at that size (median) | Restart and recover |
|---|---|---|---|---|---|---|---|---|
| 2 | 219 | 343 | 191,748 | 174,236 | 4 | 39 to 43 ms | 8.0 to 9.2 ms | 48 to 51 ms |
| 3 | 260 | 384 | 221,355 | 188,442 | 7 | 71 to 75 ms | 8.0 to 8.2 ms | 48 to 52 ms |
| 8 | 465 | 589 | 371,724 | 259,472 | 22 | 269 to 277 ms | 8.0 ms | 61 ms |

The snapshot of each size holds 206 bytes more than the round 2 figures
(191,542, 221,149 and 371,518): the checkpoint of the roster the last install
replaced (24 bytes of framing and the one-member genesis roster, 0145). A
checkpoint of a replaced roster of eight members with 32-byte identities is 489
bytes.

A logical send costs one commit for the intent and three per recipient (prepare,
reserve, accept), each rewriting the whole snapshot, so the time of a send grows
with the number of recipients times the snapshot size. The probe process's
maximum resident set was 15 MB, 17 MB and 23 MB and its user CPU 0.25 s, 0.39 s
and 1.05 s at 2, 3 and 8 members.

Steady state, from the second probe: eight members, the authority sends
seventeen 1,000-byte messages in a row (each delivered to all seven recipients),
and the last is timed. The snapshot keeps every live send and the sixteen most
recent terminal ones (0133), so it grows by about 90 KB per send until sixteen
are retained (371,724 bytes for the first send, 462,143 for the second, 1,004,657
for the eighth) and then stays at its ceiling.

| Members | Sends | Snapshot bytes | Provider state | Outbox records | Commits per logical send | Last logical send | Terminal sends retained |
|---|---|---|---|---|---|---|---|
| 8 | 17 | 1,728,009 | 259,472 | 352 | 22 | 587 to 596 ms | 16 |

That is 4.6 times the snapshot and about 2.2 times the time of the first send,
and 1.47 MB of the snapshot is the outbox and the other collections, not the
provider state (259,472 bytes) or the receiver state (589 bytes). The probe
process's maximum resident set was 41 MB and its user CPU 5.6 s. The whole demo
in one process, which ran 448 tests when this was measured (it runs 466 now: the wire-vector and encoder-refusal tests came later): 86 s elapsed (345 s CPU, 900 MB) cold and
59 s (279 s CPU, 100 MB) warm, at that load. Nothing was measured at 32, 128 or
512 members, with the outbox holding its eight live sends, or on another host,
and the commit latency was measured at the sizes of the first table only.

```bash
tooling/measure-group-chat.sh /tmp/tacenta-group-measurements
```

To check that the group crate's tests notice a removed guard, run its
single-change mutation harness (134 mutants; a few minutes with four workers,
longer on a loaded machine). It needs the unmodified tree to pass, prints each
mutant as killed or survived, and fails on a mutant that does not patch or build:

```bash
python3 tooling/group-mutation/mutate.py --workers 4
```

At the revision that added mutants R22 to R24 it killed 127 and left seven
standing, the same seven as before, each argued: `L05` (the 4,096-byte roster bound is above the largest
valid roster, 3,048 bytes, so nothing reaches it), `L10` and `S11` (a second
check returns the same error; the pair with both removed, `D10` and `D11`, is
killed), `N13` (the duplicate lookup runs before the sequence-order check),
`N36` (`Roster::validate` already enforces the genesis shape, so every roster
that reaches `accept_source` at revision zero passes the genesis checks),
`P01` (the 8 KiB payload-input bound is an early exit that gives the error the
length check gives) and `X15` (a third reserved attempt already exhausts the
recipient). These are arguments from the code, not proofs of equivalence. The
harness covers the group crate only; the client and transport crates have no
harness in this repository.

Many comments in the group tests name a mutant by an id (`M###`, `R###`, `D##`)
and a `file:line`. Those ids belong to single-change mutation runs against
97689a0, 341e2b0 and later revisions whose mutant lists are **not kept in this
repository**; only the ids of `tooling/group-mutation/mutants.py` (the letters
`L`, `N`, `P`, `R`, `S`, `V` and `X`, and `D` for its doubles) resolve here, and
its `R` ids are not those of the comments. The line numbers in the comments are
those of the commit the comment names and have drifted. A comment states the one
change its test fails on in words, and that is what to read.

## 5. The repo gates

```bash
cd tacenta
for s in tooling/check-*.sh; do echo "== $s =="; bash "$s"; done
# check-docs-match.sh resolves citations across both trees, so point it at a
# checkout of tacenta-core at the pinned revision:
TACENTA_CORE_DIR=/path/to/tacenta-core bash tooling/check-docs-match.sh
```

## The axiom baselines (what a green proof rests on)

- **Spec-level theorems.** Today none of them depends on an axiom beyond
  `propext` and `Quot.sound` (the wire theorems and two of the four bounded-group
  theorems use the second; the others need at most `propext`). What is enforced
  is narrower than that: `spec/Tacenta/Assurance.lean` pins the exact axiom set
  of the 47 theorems it lists with `#guard_msgs in #print axioms`, of the 90
  `theorem`s that `spec/Tacenta` declares, and the four group theorems are among
  the 47. An added axiom, a `sorry` or `Classical.choice` in a listed theorem
  fails the build. **It does not catch** a theorem weakened with the same axioms
  (`True` as its statement), a new theorem that is not listed and is built on an
  added axiom, `native_decide` in an `example`, or a theorem missing from the
  list; a `sorry` in an unlisted theorem fails the CI step that searches the
  build log for `declaration uses`. The group model, its vectors and its
  theorems have had no human review.
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
