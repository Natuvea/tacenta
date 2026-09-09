# 0075 -- tacenta-core is the sole cryptographic provider

## Decision

**tacenta-core is the only cryptographic provider in the product.** Every
key agreement, ratchet step, signature and authenticated encryption the SDK
performs is performed by tacenta-core, an independent implementation of the
published Signal Protocol specifications, consumed as a pinned dependency
(`Cargo.toml` pins the public repository at a fixed revision, under the alias
`open-tacenta` because this repository's integration crate is also called
`tacenta-core`). The product contributes no cryptography of its own: nothing in
this tree derives a key, authenticates a message or chooses a primitive. The
provider seam has one implementation, and the conformance suite checks it
against the seam's behavioural contract.

## The dependency graph

The product's dependency graph contains no libsignal crate and no GPL, AGPL or
other strong-copyleft dependency. Permissive and file-level licences -- MIT,
Apache-2.0, and MPL-2.0 (the last via UniFFI) -- are present and permitted.

Two checks hold this on every run:

- `tooling/check-licences.sh` resolves the full build graph and fails if a
  strong-copyleft crate reaches it.
- `tooling/check-tree-clean.sh` refuses tracked object code and build output,
  so nothing compiled can carry a dependency the manifest does not declare.

The graph is the claim, and the checks are how the claim is made rather than
asserted.

## Distribution

Packages are published only from a graph the checks above certify. A build
whose graph does not pass `check-licences.sh` and `check-tree-clean.sh` is not a
release candidate; the SDK packages reach a registry only after the clean-room
evidence packet has been verified against the exact commits the artifacts are
built from.

## The clean-room method

tacenta-core is developed and maintained in its own public repository under the
Apache-2.0 licence. The policy it is built to is that repository's ADR-0003, as amended by
its ADR-0005. The provenance note for this product is
`docs/clean-room-provenance.md`.

## What would reopen this

- A dependency that carries a strong-copyleft licence for a reason worth
  having. The checks fail closed; the decision to admit it would be recorded
  here before the check is changed.
