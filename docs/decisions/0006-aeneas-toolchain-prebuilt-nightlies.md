# 0006 — Aeneas toolchain: prebuilt nightlies, pinned together

## Decision

The Rust-to-Lean verification pipeline uses the prebuilt nightly
binaries published by the AeneasVerif releases — Charon (Rust → LLBC)
and Aeneas (LLBC → Lean) — installed machine-locally (a local install directory, overridable via
`AENEAS_TOOLS`), not built from source and not vendored into the repo.

Current pin, which moves as ONE unit:

- Charon: release `nightly-2026.07.22` (requires rustc
  `nightly-2026-06-01` with `rustc-dev`, installed via rustup)
- Aeneas: release `nightly-2026.07.22-b1214ca`
- Aeneas Lean library: same tag, required by `verification/lakefile.toml`
  with `subDir = "backends/lean"`; its toolchain is `lean4:v4.31.0`,
  deliberately identical to `spec/lean-toolchain`

`tooling/run-aeneas.sh` runs the pipeline; the generated Lean under
`verification/Verification/Generated/` is committed, the intermediate
`.llbc` is not.

## Considered

- **Building Charon + Aeneas from source.** Needs an OCaml/opam (or
  nix) toolchain, for no gain while the project tracks upstream
  nightlies anyway.
- **Vendoring the binaries into the repo.** 100 MB+ of binaries in git
  for tools that update daily; the pin in this record plus the download
  command is strictly better.
- **Generating the Lean in CI instead of committing it.** Would need
  Charon's exact rustc nightly plus the tools on every runner; and an
  uncommitted translation cannot be read in a diff. Committing the
  generated file makes translation drift visible in the diff, like the
  conformance vectors.

## Why

Upstream now ships macOS/Linux binaries for every nightly, which
removes the entire OCaml build burden — the pipeline here is download,
pin, run. The three components interlock (LLBC format ↔ translator ↔
Lean library API), so they are pinned to the same nightly and bumped
together, never independently. Keeping the Lean toolchain identical
between `spec/` and `verification/` means one elan install serves both
and the two lake packages can share proof infrastructure later.

## What would reopen this

- An Aeneas or Charon stable release channel — move off nightlies.
- The verification package needing patches to the Aeneas Lean library —
  would force a fork-and-pin instead of the release require.
- CI needing to regenerate (not just build) the translation — would
  need the tools + rustc nightly provisioned on runners; take the cost
  only when a drift-check gate for the generated file is wanted.
