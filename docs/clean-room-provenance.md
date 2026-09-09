# Clean-room provenance

The cryptography in Tacenta is **tacenta-core**, an independent implementation
of the published Signal Protocol specifications (X3DH, PQXDH, the Double
Ratchet, the ML-KEM Braid post-quantum ratchet, and XEdDSA), developed and
maintained in its own repository under the Apache-2.0 licence.

tacenta-core was written from the published specifications and the standards
they cite. The exact revisions it targets are pinned by SHA-256 in
`docs/references/README.md`. The work is done under tacenta-core's ADR-0003
and ADR-0005.

This product consumes tacenta-core as a pinned dependency — `Cargo.toml` pins
the public repository at a 40-character revision — and contributes no
cryptography of its own. Decision record
`docs/decisions/0075-tacenta-core-is-the-sole-crypto-provider.md` is the
provider decision.

The product's dependency graph contains no libsignal crate and no AGPL or GPL
code. `tooling/check-licences.sh` resolves the build graph on every run and
fails if a strong-copyleft crate reaches it; `tooling/check-tree-clean.sh`
refuses tracked build output.

tacenta-core and Tacenta are not affiliated with, endorsed by, or sponsored by
Signal Messenger LLC or the Signal Foundation. "Signal" is used only to name
the published protocol specifications.
